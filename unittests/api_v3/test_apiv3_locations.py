"""
Locations resource + finding/product location sub-resources for API v3 (§4.14, OS4).

Covers: the read-only ``/locations`` resource (slim/detail shapes incl. URL-subtype fields, filters,
orderings, pagination, the v2 superuser-only RBAC mirror, constant query count); the
``/findings/{id}/locations`` and ``/products/{id}/locations`` edge sub-resources (edge shapes,
auditor ref, parent-inherited authorization 404, pagination, constant query count); the
``?fields=`` / ``?expand=`` interplay; and flag-off behaviour (whole /api/v3-alpha/ tree absent).
"""
from __future__ import annotations

import importlib

from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import Resolver404, clear_url_caches, resolve
from django.utils import timezone

import dojo.urls
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.models import Finding, Product, User

from .base import ApiV3TestCase

_SLIM_KEYS = {"id", "name", "type", "tags"}
_DETAIL_KEYS = _SLIM_KEYS | {"protocol", "host", "port", "path", "query", "fragment"}
_FINDING_EDGE_KEYS = {"location", "status", "audit_time", "auditor"}
_PRODUCT_EDGE_KEYS = {"location", "status"}
_LOCATION_REF_KEYS = {"id", "name", "type"}


class TestApiV3LocationsRead(ApiV3TestCase):

    """The read-only /locations resource (admin is a superuser, so RBAC never hides rows here)."""

    def test_list_envelope_and_slim_shape(self):
        body = self.get_json("locations")
        self.assertEqual({"count", "next", "previous", "results"}, set(body) - {"meta"})
        self.assertGreater(body["count"], 0)
        row = body["results"][0]
        self.assertEqual(_SLIM_KEYS, set(row))
        self.assertIsInstance(row["tags"], list)
        self.assertEqual("url", row["type"])

    def test_detail_adds_url_subtype_fields(self):
        # Fixture Location 1 is http://127.0.0.1/endpoint/420/edit/ (URL subtype pk 1).
        detail = self.get_json("locations/1")
        self.assertEqual(_DETAIL_KEYS, set(detail))
        self.assertEqual("url", detail["type"])
        self.assertEqual("http://127.0.0.1/endpoint/420/edit/", detail["name"])
        self.assertEqual("http", detail["protocol"])
        self.assertEqual("127.0.0.1", detail["host"])
        self.assertEqual(80, detail["port"])
        self.assertEqual("endpoint/420/edit/", detail["path"])
        self.assertEqual("", detail["query"])
        self.assertEqual("", detail["fragment"])

    def test_detail_unknown_is_404_problem(self):
        response = self.client.get(self.v3_url("locations/99999999"))
        self.assertEqual(404, response.status_code)
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_filter_type(self):
        body = self.get_json("locations", data={"type": "url", "limit": 250})
        self.assertGreater(body["count"], 0)
        for row in body["results"]:
            self.assertEqual("url", row["type"])
        # No non-url locations exist in alpha; a bogus type returns nothing.
        self.assertEqual(0, self.get_json("locations", data={"type": "code"})["count"])

    def test_filter_name_icontains(self):
        body = self.get_json("locations", data={"name__icontains": "bar.foo", "limit": 250})
        self.assertGreater(body["count"], 0)
        for row in body["results"]:
            self.assertIn("bar.foo", row["name"])

    def test_filter_product(self):
        # Fixture: LocationProductReference links product 1 -> location 6.
        body = self.get_json("locations", data={"product": 1, "limit": 250})
        ids = {row["id"] for row in body["results"]}
        self.assertIn(6, ids)

    def test_ordering_by_name(self):
        names = [r["name"] for r in self.get_json("locations", data={"o": "name", "limit": 250})["results"]]
        self.assertEqual(names, sorted(names))

    def test_ordering_by_id_desc(self):
        ids = [r["id"] for r in self.get_json("locations", data={"o": "-id", "limit": 250})["results"]]
        self.assertEqual(ids, sorted(ids, reverse=True))

    def test_pagination_envelope(self):
        body = self.get_json("locations", data={"limit": 2, "offset": 2})
        self.assertLessEqual(len(body["results"]), 2)
        self.assertIsNotNone(body["previous"])

    def test_unknown_filter_param_is_400(self):
        self.get_json("locations", data={"not_a_filter": "x"}, expected=400)

    def test_unknown_field_is_400(self):
        self.get_json("locations", data={"fields": "id,not_a_field"}, expected=400)


class TestApiV3LocationsRbac(ApiV3TestCase):

    """/locations mirrors v2 LocationViewSet exactly: superuser-only (IsSuperUser) -> 403 otherwise."""

    def setUp(self):
        super().setUp()
        self.regular = User.objects.create_user(username="v3_loc_regular", password="x")  # noqa: S106

    def test_non_superuser_list_is_403(self):
        client = self.token_client(user=self.regular)
        response = client.get(self.v3_url("locations"))
        self.assertEqual(403, response.status_code, response.content[:300])
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_non_superuser_detail_is_403(self):
        client = self.token_client(user=self.regular)
        response = client.get(self.v3_url("locations/1"))
        self.assertEqual(403, response.status_code, response.content[:300])

    def test_superuser_can_read(self):
        self.assertGreater(self.get_json("locations")["count"], 0)
        self.get_json("locations/1")


class TestApiV3LocationsQueryCount(ApiV3TestCase):

    def _query_count(self, params: dict) -> int:
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(self.v3_url("locations"), params)
            self.assertEqual(200, response.status_code, response.content[:500])
        return len(ctx.captured_queries)

    def test_query_count_is_independent_of_row_count(self):
        Location.objects.bulk_create([
            Location(location_type="url", location_value=f"https://qcount.example/{i}") for i in range(10)
        ])
        first = self._query_count({"limit": 250})
        Location.objects.bulk_create([
            Location(location_type="url", location_value=f"https://qcount.example/b{i}") for i in range(90)
        ])
        second = self._query_count({"limit": 250})
        self.assertEqual(first, second, f"query count grew with row count: {first} -> {second}")


class TestApiV3FindingLocationsSubResource(ApiV3TestCase):

    """GET /findings/{id}/locations edge rows: location ref + status/audit_time/auditor (§4.14)."""

    def _attach(self, finding, value, status="Active", auditor=None, audit_time=None):
        location = Location.objects.create(location_type="url", location_value=value)
        return LocationFindingReference.objects.create(
            location=location, finding=finding, status=status, auditor=auditor, audit_time=audit_time,
        )

    def test_edge_shape_and_location_ref(self):
        # Fixture finding 227 already has three location edges (5/6/7).
        body = self.get_json("findings/227/locations")
        self.assertEqual({"count", "next", "previous", "results"}, set(body) - {"meta"})
        self.assertEqual(3, body["count"])
        for row in body["results"]:
            self.assertEqual(_FINDING_EDGE_KEYS, set(row))
            self.assertEqual(_LOCATION_REF_KEYS, set(row["location"]))
            self.assertEqual("url", row["location"]["type"])
            self.assertIsNone(row["auditor"])  # fixture edges carry no auditor

    def test_status_values_pass_through(self):
        finding = Finding.objects.get(pk=228)  # fixture: one FalsePositive edge on location 5
        rows = self.get_json(f"findings/{finding.id}/locations")["results"]
        self.assertEqual(["FalsePositive"], [r["status"] for r in rows])

    def test_auditor_ref_rendered(self):
        finding = Finding.objects.get(pk=2)
        when = timezone.now()
        self._attach(finding, "https://audited.example/a", auditor=self.admin, audit_time=when)
        rows = self.get_json(f"findings/{finding.id}/locations")["results"]
        audited = [r for r in rows if r["auditor"] is not None]
        self.assertEqual(1, len(audited))
        self.assertEqual({"id", "name"}, set(audited[0]["auditor"]))
        self.assertEqual(self.admin.id, audited[0]["auditor"]["id"])
        self.assertEqual(self.admin.username, audited[0]["auditor"]["name"])
        self.assertIsNotNone(audited[0]["audit_time"])

    def test_unknown_parent_is_404(self):
        response = self.client.get(self.v3_url("findings/99999999/locations"))
        self.assertEqual(404, response.status_code)
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_unauthorized_parent_is_404(self):
        # A user with no product access cannot see finding 227 -> parent-inherited 404 (not 403).
        limited = User.objects.create_user(username="v3_loc_findlimited", password="x")  # noqa: S106
        client = self.token_client(user=limited)
        response = client.get(self.v3_url("findings/227/locations"))
        self.assertEqual(404, response.status_code, response.content[:300])

    def test_pagination_envelope(self):
        finding = Finding.objects.get(pk=2)
        for i in range(5):
            self._attach(finding, f"https://page.example/{i}")
        body = self.get_json(f"findings/{finding.id}/locations", data={"limit": 2, "offset": 2})
        self.assertLessEqual(len(body["results"]), 2)
        self.assertIsNotNone(body["previous"])

    def test_query_count_is_independent_of_edge_count(self):
        finding = Finding.objects.get(pk=2)

        def query_count() -> int:
            with CaptureQueriesContext(connection) as ctx:
                response = self.client.get(self.v3_url(f"findings/{finding.id}/locations"), {"limit": 250})
                self.assertEqual(200, response.status_code, response.content[:500])
            return len(ctx.captured_queries)

        for i in range(5):
            self._attach(finding, f"https://qc.example/{i}", auditor=self.admin)
        first = query_count()
        for i in range(20):
            self._attach(finding, f"https://qc.example/b{i}", auditor=self.admin)
        second = query_count()
        self.assertEqual(first, second, f"sub-resource query count grew: {first} -> {second}")


class TestApiV3ProductLocationsSubResource(ApiV3TestCase):

    """GET /products/{id}/locations edge rows: location ref + status only (no audit columns, §12)."""

    def _attach(self, product, value, status="Active"):
        location = Location.objects.create(location_type="url", location_value=value)
        return LocationProductReference.objects.create(location=location, product=product, status=status)

    def test_edge_shape_and_location_ref(self):
        # Fixture: product 1 -> location 6 (Active).
        body = self.get_json("products/1/locations")
        self.assertEqual({"count", "next", "previous", "results"}, set(body) - {"meta"})
        self.assertGreaterEqual(body["count"], 1)
        row = next(r for r in body["results"] if r["location"]["id"] == 6)
        self.assertEqual(_PRODUCT_EDGE_KEYS, set(row))
        self.assertEqual(_LOCATION_REF_KEYS, set(row["location"]))
        self.assertEqual("url", row["location"]["type"])
        self.assertEqual("Active", row["status"])

    def test_unknown_parent_is_404(self):
        response = self.client.get(self.v3_url("products/99999999/locations"))
        self.assertEqual(404, response.status_code)
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_unauthorized_parent_is_404(self):
        limited = User.objects.create_user(username="v3_loc_prodlimited", password="x")  # noqa: S106
        client = self.token_client(user=limited)
        response = client.get(self.v3_url("products/1/locations"))
        self.assertEqual(404, response.status_code, response.content[:300])

    def test_query_count_is_independent_of_edge_count(self):
        product = Product.objects.get(pk=1)

        def query_count() -> int:
            with CaptureQueriesContext(connection) as ctx:
                response = self.client.get(self.v3_url(f"products/{product.id}/locations"), {"limit": 250})
                self.assertEqual(200, response.status_code, response.content[:500])
            return len(ctx.captured_queries)

        for i in range(5):
            self._attach(product, f"https://pqc.example/{i}")
        first = query_count()
        for i in range(20):
            self._attach(product, f"https://pqc.example/b{i}")
        second = query_count()
        self.assertEqual(first, second, f"sub-resource query count grew: {first} -> {second}")


class TestApiV3FieldsExpandInterplay(ApiV3TestCase):

    """The ?fields= allowlist = schema fields + registered EXPANDABLE keys (OS4 item 4, §12)."""

    def test_expand_key_accepted_in_fields(self):
        # `locations` is an expandable key, not a model field; it must be nameable in ?fields=.
        finding = Finding.objects.get(pk=227)
        body = self.get_json(
            "findings", data={"expand": "locations", "fields": "id,title,locations", "id__in": finding.id},
        )
        row = next(r for r in body["results"] if r["id"] == finding.id)
        self.assertEqual({"id", "title", "locations"}, set(row))
        self.assertNotIn("locations_count", row)
        self.assertGreater(len(row["locations"]), 0)

    def test_fields_without_expand_drops_expand_key_silently(self):
        # Naming an expand key in ?fields= without ?expand= is accepted (no 400) but renders nothing.
        row = self.get_json("findings", data={"fields": "id,title,locations"})["results"][0]
        self.assertEqual({"id", "title"}, set(row))

    def test_unknown_field_still_400(self):
        self.get_json("findings", data={"fields": "id,definitely_not_a_field"}, expected=400)

    def test_unknown_field_alongside_expand_key_still_400(self):
        self.get_json(
            "findings", data={"expand": "locations", "fields": "id,locations,bogus_field"}, expected=400,
        )


class TestApiV3LocationsFlagOff(ApiV3TestCase):

    """With V3_FEATURE_LOCATIONS=False the entire /api/v3-alpha/ tree is unmounted (D5/§4.1)."""

    def test_flag_off_unmounts_entire_v3_tree(self):
        # Flag is on in the test settings: the whole v3 tree resolves.
        resolve(self.v3_url("locations"))
        resolve(self.v3_url("findings"))

        try:
            with override_settings(V3_FEATURE_LOCATIONS=False):
                clear_url_caches()
                importlib.reload(dojo.urls)
                # Nothing under the v3 prefix resolves once the flag is off -- the mount is gone.
                for path in ("locations", "findings", "products", "import"):
                    with self.assertRaises(Resolver404):
                        resolve(self.v3_url(path), urlconf=dojo.urls)
        finally:
            # Restore the real (flag-on) URLconf for the rest of the suite.
            clear_url_caches()
            importlib.reload(dojo.urls)

        # Restored: the v3 tree resolves again.
        resolve(self.v3_url("locations"))
