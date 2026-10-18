"""
Writes through the legacy Endpoint API on an instance with Locations enabled.

With ``V3_FEATURE_LOCATIONS`` on, ``/api/v2/endpoints`` and ``/api/v2/endpoint_status``
are served from Locations. A legacy client keeps sending Endpoint and Endpoint_Status
payloads, so each write has to land on the Location rows it stands for: an endpoint is one
product's ``LocationProductReference`` to a URL Location, an endpoint status is a
``LocationFindingReference``. A Location is shared by every product that recorded the same
URL, which a legacy Endpoint never was, so these tests also pin that a write for one
product leaves the other products' rows alone.
"""

import pghistory.models
from django.apps import apps
from django.test import override_settings
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.location.status import FindingLocationStatus, ProductLocationStatus
from dojo.models import (
    Dojo_User,
    DojoMeta,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
    UserContactInfo,
)
from dojo.url.models import URL

from .dojo_test_case import DojoTestCase, skip_unless_v3
from .test_rest_framework import BASE_API_URL

ENDPOINTS = f"{BASE_API_URL}/endpoints/"
ENDPOINT_STATUS = f"{BASE_API_URL}/endpoint_status/"


def _client(user):
    token, _ = Token.objects.get_or_create(user=user)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
    return client


class _CompatFixture(DojoTestCase):

    """Two products, each with a finding, and a superuser plus a member of the second product only."""

    def setUp(self):
        super().setUp()
        self.admin = Dojo_User.objects.create(username="compat_writes_admin", is_staff=True, is_superuser=True)
        UserContactInfo.objects.create(user=self.admin, block_execution=True)
        self.client = _client(self.admin)

        prod_type = Product_Type.objects.create(name="compat_writes_pt")
        self.product_a = Product.objects.create(name="compat_writes_a", description="x", prod_type=prod_type)
        self.product_b = Product.objects.create(name="compat_writes_b", description="x", prod_type=prod_type)
        self.finding_a = self._finding(self.product_a, "a")
        self.finding_a2 = self._finding(self.product_a, "a2")
        self.finding_b = self._finding(self.product_b, "b")

        self.member_b = Dojo_User.objects.create(username="compat_writes_member_b", is_staff=False, is_superuser=False)
        self.product_b.authorized_users.add(self.member_b)

    def _finding(self, product, name):
        engagement = Engagement.objects.create(
            name=f"compat_writes_eng_{name}",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        test = Test.objects.create(
            engagement=engagement,
            test_type=Test_Type.objects.get_or_create(name="compat_writes_scan")[0],
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        return Finding.objects.create(
            test=test,
            title=f"compat_writes_finding_{name}",
            description="x",
            severity="High",
            numerical_severity="S0",
            active=True,
            verified=True,
            reporter=self.admin,
        )

    def _shared_location(self, host="shared.example.com"):
        """One URL Location recorded by both products, each with a finding on it."""
        url = URL.get_or_create_from_values(protocol="https", host=host)
        location = url.location
        location.associate_with_finding(self.finding_a)
        location.associate_with_finding(self.finding_b)
        return location

    def _endpoint(self, location, product):
        return LocationProductReference.objects.get(location=location, product=product)

    def _post_endpoint(self, client=None, **fields):
        payload = {"protocol": "https", "host": "new.example.com", "product": self.product_a.id, **fields}
        return (client or self.client).post(ENDPOINTS, payload, format="json")


@skip_unless_v3
@override_settings(SECURE_SSL_REDIRECT=False)
class EndpointWriteThroughTests(_CompatFixture):

    def test_create_records_a_url_location_on_the_product(self):
        response = self._post_endpoint(port=8443, path="/login", query="a=b", fragment="top")

        self.assertEqual(201, response.status_code, response.content)
        body = response.json()
        reference = LocationProductReference.objects.get(id=body["id"])
        self.assertEqual(self.product_a, reference.product)
        self.assertEqual(body["location_id"], reference.location_id)
        url = reference.location.url
        self.assertEqual(
            ("https", "new.example.com", 8443, "login", "a=b", "top"),
            (url.protocol, url.host, url.port, url.path, url.query, url.fragment),
        )
        # The row a read returns for the same id, as legacy clients expect after a create.
        read = self.client.get(f"{ENDPOINTS}{body['id']}/", format="json").json()
        read.pop("prefetch", None)
        self.assertEqual(body, read)

    def test_create_reuses_the_location_another_product_recorded(self):
        location = self._shared_location()
        LocationProductReference.objects.filter(location=location, product=self.product_a).delete()

        response = self._post_endpoint(host="shared.example.com")

        self.assertEqual(201, response.status_code, response.content)
        self.assertEqual(location.id, response.json()["location_id"])
        self.assertEqual(2, LocationProductReference.objects.filter(location=location).count())

    def test_create_duplicate_for_the_product_is_rejected(self):
        self.assertEqual(201, self._post_endpoint().status_code)
        response = self._post_endpoint()
        self.assertEqual(400, response.status_code, response.content)
        self.assertIn("already exists for this product", response.content.decode())

    def test_create_without_a_host_is_rejected(self):
        response = self._post_endpoint(host="")
        self.assertEqual(400, response.status_code, response.content)
        self.assertIn("Host must not be empty", response.content.decode())

    def test_tags_on_a_location_another_product_shares_are_refused_for_a_member(self):
        # member_b can edit product B but not product A, and the Location is on both, so its
        # one tag set is not theirs to change.
        location = self._shared_location()
        endpoint_b = self._endpoint(location, self.product_b)
        member = _client(self.member_b)

        response = member.patch(f"{ENDPOINTS}{endpoint_b.id}/", {"tags": ["mine"]}, format="json")

        self.assertEqual(400, response.status_code, response.content)
        self.assertIn("shared with an asset you cannot edit", response.content.decode())
        self.assertEqual([], list(location.tags.all()))

    def test_tags_on_a_location_one_product_owns_are_written(self):
        location = URL.get_or_create_from_values(protocol="https", host="own.example.com").location
        endpoint_b = location.associate_with_product(self.product_b)

        response = _client(self.member_b).patch(f"{ENDPOINTS}{endpoint_b.id}/", {"tags": ["mine"]}, format="json")

        self.assertEqual(200, response.status_code, response.content)
        self.assertEqual(["mine"], response.json()["tags"])
        self.assertEqual(["mine"], [tag.name for tag in location.tags.all()])

    def test_patch_changes_the_address_in_place_when_one_product_owns_the_location(self):
        location = URL.get_or_create_from_values(protocol="https", host="old.example.com").location
        location.associate_with_finding(self.finding_a)
        endpoint = self._endpoint(location, self.product_a)

        response = self.client.patch(f"{ENDPOINTS}{endpoint.id}/", {"host": "renamed.example.com"}, format="json")

        self.assertEqual(200, response.status_code, response.content)
        self.assertEqual(location.id, response.json()["location_id"])
        self.assertEqual("renamed.example.com", URL.objects.get(location=location).host)
        self.assertTrue(LocationFindingReference.objects.filter(location=location, finding=self.finding_a).exists())

    def test_patch_on_a_shared_location_moves_only_this_products_endpoint(self):
        location = self._shared_location()
        endpoint_a = self._endpoint(location, self.product_a)
        DojoMeta.objects.create(name="owner", value="team-a", location=location, location_product=self.product_a)

        response = self.client.patch(f"{ENDPOINTS}{endpoint_a.id}/", {"host": "moved.example.com"}, format="json")

        self.assertEqual(200, response.status_code, response.content)
        endpoint_a.refresh_from_db()
        self.assertEqual(endpoint_a.id, response.json()["id"])
        self.assertEqual("moved.example.com", endpoint_a.location.url.host)
        # Product A's finding and metadata went with its endpoint.
        self.assertTrue(LocationFindingReference.objects.filter(location=endpoint_a.location, finding=self.finding_a).exists())
        self.assertTrue(DojoMeta.objects.filter(location=endpoint_a.location, location_product=self.product_a, name="owner").exists())
        # Product B still sees the original address with its own finding.
        self.assertEqual("shared.example.com", URL.objects.get(location=location).host)
        self.assertTrue(LocationProductReference.objects.filter(location=location, product=self.product_b).exists())
        self.assertTrue(LocationFindingReference.objects.filter(location=location, finding=self.finding_b).exists())
        self.assertFalse(LocationFindingReference.objects.filter(location=location, finding=self.finding_a).exists())

    def test_a_refused_tag_write_takes_back_the_address_change(self):
        # Moving product B's endpoint onto a URL product A already recorded makes that Location
        # shared with an asset member_b cannot edit, so the tags are refused and nothing moves.
        own = URL.get_or_create_from_values(protocol="https", host="b-own.example.com").location
        endpoint_b = own.associate_with_product(self.product_b)
        URL.get_or_create_from_values(protocol="https", host="a-own.example.com").location.associate_with_product(self.product_a)

        response = _client(self.member_b).patch(
            f"{ENDPOINTS}{endpoint_b.id}/",
            {"host": "a-own.example.com", "tags": ["mine"]},
            format="json",
        )

        self.assertEqual(400, response.status_code, response.content)
        endpoint_b.refresh_from_db()
        self.assertEqual(own.id, endpoint_b.location_id)
        self.assertEqual("b-own.example.com", URL.objects.get(location=own).host)

    def test_patch_to_an_address_the_product_already_has_is_rejected(self):
        first = self._post_endpoint(host="one.example.com").json()
        self._post_endpoint(host="two.example.com")

        response = self.client.patch(f"{ENDPOINTS}{first['id']}/", {"host": "two.example.com"}, format="json")

        self.assertEqual(400, response.status_code, response.content)
        self.assertIn("already exists for this product", response.content.decode())

    def test_delete_on_a_shared_location_removes_only_this_products_rows(self):
        location = self._shared_location()
        endpoint_a = self._endpoint(location, self.product_a)
        DojoMeta.objects.create(name="owner", value="team-a", location=location, location_product=self.product_a)

        response = self.client.delete(f"{ENDPOINTS}{endpoint_a.id}/")

        self.assertEqual(204, response.status_code, response.content)
        self.assertFalse(LocationProductReference.objects.filter(id=endpoint_a.id).exists())
        self.assertFalse(LocationFindingReference.objects.filter(location=location, finding=self.finding_a).exists())
        self.assertFalse(DojoMeta.objects.filter(location=location, location_product=self.product_a).exists())
        self.assertTrue(Location.objects.filter(id=location.id).exists())
        self.assertTrue(LocationFindingReference.objects.filter(location=location, finding=self.finding_b).exists())

    def test_delete_of_the_last_reference_deletes_the_location(self):
        location = URL.get_or_create_from_values(protocol="https", host="alone.example.com").location
        location.associate_with_finding(self.finding_a)
        endpoint = self._endpoint(location, self.product_a)

        response = self.client.delete(f"{ENDPOINTS}{endpoint.id}/")

        self.assertEqual(204, response.status_code, response.content)
        self.assertFalse(Location.objects.filter(id=location.id).exists())

    def test_member_without_rights_on_the_product_cannot_create_there(self):
        response = self._post_endpoint(client=_client(self.member_b))
        self.assertEqual(403, response.status_code, response.content)
        self.assertFalse(URL.objects.filter(host="new.example.com").exists())

    def test_generate_report_reports_on_the_products_findings_on_that_host(self):
        location = self._shared_location()
        endpoint_a = self._endpoint(location, self.product_a)

        response = self.client.post(f"{ENDPOINTS}{endpoint_a.id}/generate_report/", {}, format="json")

        self.assertEqual(200, response.status_code, response.content)
        body = response.json()
        self.assertEqual("shared.example.com", body["endpoint"]["host"])
        self.assertEqual([endpoint_a.id], [row["id"] for row in body["endpoints"]])
        self.assertEqual([self.finding_a.id], [row["id"] for row in body["findings"]])

    def test_writes_carry_the_endpoint_api_pghistory_source(self):
        url_event = apps.get_model("dojo", "URLEvent")

        response = self._post_endpoint(host="audited.example.com")

        self.assertEqual(201, response.status_code, response.content)
        event = url_event.objects.filter(host="audited.example.com").latest("pgh_created_at")
        context = pghistory.models.Context.objects.get(id=event.pgh_context_id)
        self.assertEqual("endpoint_api_compat", context.metadata.get("source"))


@skip_unless_v3
@override_settings(SECURE_SSL_REDIRECT=False)
class EndpointStatusWriteThroughTests(_CompatFixture):

    def setUp(self):
        super().setUp()
        location = URL.get_or_create_from_values(protocol="https", host="status.example.com").location
        self.endpoint = location.associate_with_product(self.product_a)
        self.location = location

    def _post_status(self, **fields):
        payload = {"endpoint": self.endpoint.id, "finding": self.finding_a.id, **fields}
        return self.client.post(ENDPOINT_STATUS, payload, format="json")

    def test_create_links_the_finding_to_the_endpoint(self):
        response = self._post_status()

        self.assertEqual(201, response.status_code, response.content)
        body = response.json()
        reference = LocationFindingReference.objects.get(id=body["id"])
        self.assertEqual((self.location, self.finding_a), (reference.location, reference.finding))
        self.assertEqual(FindingLocationStatus.Active, reference.status)
        self.assertEqual(self.endpoint.id, body["endpoint"])
        self.assertFalse(body["mitigated"])
        self.endpoint.refresh_from_db()
        self.assertEqual(ProductLocationStatus.Active, self.endpoint.status)

    def test_create_mitigated_records_who_and_when(self):
        before = timezone.now()
        response = self._post_status(mitigated=True)

        self.assertEqual(201, response.status_code, response.content)
        body = response.json()
        reference = LocationFindingReference.objects.get(id=body["id"])
        self.assertEqual(FindingLocationStatus.Mitigated, reference.status)
        self.assertEqual(self.admin, reference.auditor)
        self.assertGreaterEqual(reference.audit_time, before)
        self.assertTrue(body["mitigated"])
        self.assertEqual(self.admin.id, body["mitigated_by"])
        self.assertIsNotNone(body["mitigated_time"])
        # The product's only finding on the URL is mitigated, so the endpoint is too.
        self.endpoint.refresh_from_db()
        self.assertEqual(ProductLocationStatus.Mitigated, self.endpoint.status)

    def test_mitigated_by_names_the_user_who_mitigated(self):
        response = self._post_status(mitigated=True, mitigated_by=self.member_b.id)

        self.assertEqual(201, response.status_code, response.content)
        self.assertEqual(self.member_b.id, response.json()["mitigated_by"])
        self.assertEqual(self.member_b, LocationFindingReference.objects.get(id=response.json()["id"]).auditor)

    def test_flag_writes_set_the_single_status(self):
        row = self._post_status().json()
        detail = f"{ENDPOINT_STATUS}{row['id']}/"

        def patch(**flags):
            response = self.client.patch(detail, flags, format="json")
            self.assertEqual(200, response.status_code, response.content)
            return response.json()

        def status():
            return LocationFindingReference.objects.get(id=row["id"]).status

        body = patch(mitigated=True)
        self.assertEqual(FindingLocationStatus.Mitigated, status())
        self.assertTrue(body["mitigated"])
        # A flag set in the request wins over the one already set.
        body = patch(false_positive=True)
        self.assertEqual(FindingLocationStatus.FalsePositive, status())
        self.assertEqual((False, True), (body["mitigated"], body["false_positive"]))
        # Clearing a flag that is not set changes nothing.
        patch(risk_accepted=False)
        self.assertEqual(FindingLocationStatus.FalsePositive, status())
        # Two flags at once resolve the way the endpoint backfill does.
        patch(out_of_scope=True, mitigated=True)
        self.assertEqual(FindingLocationStatus.OutOfScope, status())
        # Clearing the flag that is set reactivates the row.
        body = patch(out_of_scope=False)
        self.assertEqual(FindingLocationStatus.Active, status())
        self.assertEqual(
            (False, False, False, False),
            (body["mitigated"], body["false_positive"], body["out_of_scope"], body["risk_accepted"]),
        )
        self.endpoint.refresh_from_db()
        self.assertEqual(ProductLocationStatus.Active, self.endpoint.status)

    def test_delete_unlinks_the_finding_and_keeps_the_endpoint(self):
        row = self._post_status().json()

        response = self.client.delete(f"{ENDPOINT_STATUS}{row['id']}/")

        self.assertEqual(204, response.status_code, response.content)
        self.assertFalse(LocationFindingReference.objects.filter(id=row["id"]).exists())
        self.assertTrue(LocationProductReference.objects.filter(id=self.endpoint.id).exists())
        self.endpoint.refresh_from_db()
        self.assertEqual(ProductLocationStatus.Mitigated, self.endpoint.status)

    def test_member_cannot_link_a_finding_in_a_product_they_cannot_edit(self):
        response = _client(self.member_b).post(
            ENDPOINT_STATUS,
            {"endpoint": self.endpoint.id, "finding": self.finding_a.id},
            format="json",
        )
        self.assertEqual(403, response.status_code, response.content)
        self.assertFalse(LocationFindingReference.objects.filter(location=self.location).exists())


@skip_unless_v3
@override_settings(SECURE_SSL_REDIRECT=False)
class EndpointStatusReadParityTests(_CompatFixture):

    """
    A status row's ``endpoint`` joins back to ``/api/v2/endpoints/``.

    A customer reported that ``/api/v2/endpoint_status/`` did not reflect a newly added
    location. The ``endpoint`` field answered the Location id, not the id of the endpoint
    row, so a client joining the two routes found nothing (or the wrong endpoint) for a new
    location, and ``?endpoint=`` matched the shared Location's statuses in every product.
    """

    def test_endpoint_field_is_the_id_the_endpoints_route_shows(self):
        location = self._shared_location()
        endpoint_a = self._endpoint(location, self.product_a)
        status_a = LocationFindingReference.objects.get(location=location, finding=self.finding_a)
        self.assertNotEqual(location.id, endpoint_a.id, "the fixture must tell the two ids apart")

        body = self.client.get(f"{ENDPOINT_STATUS}{status_a.id}/", format="json").json()

        self.assertEqual(endpoint_a.id, body["endpoint"])
        endpoint = self.client.get(f"{ENDPOINTS}{body['endpoint']}/", format="json").json()
        self.assertEqual((location.id, self.product_a.id), (endpoint["location_id"], endpoint["product"]))

    def test_endpoint_filter_returns_that_products_statuses_only(self):
        location = self._shared_location()
        endpoint_a = self._endpoint(location, self.product_a)

        response = self.client.get(ENDPOINT_STATUS, {"endpoint": endpoint_a.id}, format="json")

        self.assertEqual(200, response.status_code, response.content)
        self.assertEqual([self.finding_a.id], [row["finding"] for row in response.json()["results"]])
