"""Organization CRUD + RBAC + contract tests for API v3 (OS3a; D11 wire rename product_type -> organization)."""
from __future__ import annotations

from unittest import mock

from django.db import connection
from django.test.utils import CaptureQueriesContext

from dojo.models import Dojo_User, Product_Type, User

from .base import ApiV3TestCase

_SLIM_KEYS = {"id", "name", "description", "critical_product", "key_product", "created", "updated"}


class TestApiV3OrganizationsRead(ApiV3TestCase):

    def test_list_envelope_and_slim_shape(self):
        body = self.get_json("organizations")
        self.assertEqual({"count", "next", "previous", "results"}, set(body) - {"meta"})
        self.assertGreater(body["count"], 0)
        self.assertEqual(_SLIM_KEYS, set(body["results"][0]))

    def test_detail_shape(self):
        pt = Product_Type.objects.first()
        detail = self.get_json(f"organizations/{pt.id}")
        self.assertEqual(pt.id, detail["id"])
        self.assertEqual(pt.name, detail["name"])

    def test_detail_unknown_is_404_problem(self):
        response = self.client.get(self.v3_url("organizations/99999999"))
        self.assertEqual(404, response.status_code)
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_fields_projection(self):
        row = self.get_json("organizations", data={"fields": "id,name"})["results"][0]
        self.assertEqual({"id", "name"}, set(row))

    def test_unknown_field_is_400(self):
        self.get_json("organizations", data={"fields": "id,nope"}, expected=400)


class TestApiV3OrganizationsFilters(ApiV3TestCase):

    def test_filter_name_icontains(self):
        pt = Product_Type.objects.first()
        body = self.get_json("organizations", data={"name__icontains": pt.name[:4]})
        self.assertGreater(body["count"], 0)

    def test_ordering_by_name(self):
        Product_Type.objects.create(name="ZZZ v3 last type")
        Product_Type.objects.create(name="AAA v3 first type")
        names = [r["name"] for r in self.get_json("organizations", data={"o": "name", "limit": 250})["results"]]
        self.assertEqual(names, sorted(names))

    def test_unknown_filter_param_is_400(self):
        self.get_json("organizations", data={"not_a_filter": "x"}, expected=400)

    def test_unknown_ordering_is_400(self):
        self.get_json("organizations", data={"o": "nope"}, expected=400)


class TestApiV3OrganizationsPagination(ApiV3TestCase):

    def test_limit_and_next(self):
        for i in range(4):
            Product_Type.objects.create(name=f"v3 page pt {i}")
        body = self.get_json("organizations", data={"limit": 2})
        self.assertLessEqual(len(body["results"]), 2)
        self.assertIsNotNone(body["next"])
        self.assertIsNone(body["previous"])


class TestApiV3OrganizationsQueryCount(ApiV3TestCase):

    def _query_count(self, params: dict) -> int:
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(self.v3_url("organizations"), params)
            self.assertEqual(200, response.status_code, response.content[:500])
        return len(ctx.captured_queries)

    def test_query_count_is_independent_of_row_count(self):
        Product_Type.objects.bulk_create([Product_Type(name=f"qcount pt {i}") for i in range(10)])
        first = self._query_count({"limit": 250})
        Product_Type.objects.bulk_create([Product_Type(name=f"qcount pt b{i}") for i in range(90)])
        second = self._query_count({"limit": 250})
        self.assertEqual(first, second, f"query count grew with rows: {first} -> {second}")


class TestApiV3OrganizationsWrite(ApiV3TestCase):

    def test_create_happy_path(self):
        response = self.client.post(
            self.v3_url("organizations"),
            {"name": "v3 created type", "description": "made by v3", "critical_product": True},
            format="json",
        )
        self.assertEqual(201, response.status_code, response.content[:500])
        body = response.json()
        self.assertEqual("v3 created type", body["name"])
        self.assertTrue(body["critical_product"])
        self.assertTrue(Product_Type.objects.filter(name="v3 created type").exists())

    def test_create_missing_required_name_is_400(self):
        response = self.client.post(self.v3_url("organizations"), {"description": "no name"}, format="json")
        self.assertEqual(400, response.status_code)
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_create_unknown_field_is_400(self):
        response = self.client.post(
            self.v3_url("organizations"), {"name": "x", "bogus_field": 1}, format="json",
        )
        self.assertEqual(400, response.status_code)

    def test_patch_partial_update(self):
        pt = Product_Type.objects.create(name="v3 patch me", description="old")
        response = self.client.patch(
            self.v3_url(f"organizations/{pt.id}"), {"description": "new"}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:500])
        self.assertEqual("new", response.json()["description"])
        pt.refresh_from_db()
        self.assertEqual("new", pt.description)
        self.assertEqual("v3 patch me", pt.name)  # untouched

    def test_delete(self):
        pt = Product_Type.objects.create(name="v3 delete me")
        response = self.client.delete(self.v3_url(f"organizations/{pt.id}"))
        self.assertEqual(204, response.status_code)
        self.assertFalse(Product_Type.objects.filter(pk=pt.id).exists())


class TestApiV3OrganizationsReplace(ApiV3TestCase):

    """PUT full-replace: reuses the create-shaped OrganizationWrite; omitted optionals reset."""

    def test_put_full_replace_resets_omitted_optionals(self):
        pt = Product_Type.objects.create(name="v3 put org", description="old", critical_product=True)
        # PUT without description / critical_product -> both reset to their schema defaults.
        response = self.client.put(
            self.v3_url(f"organizations/{pt.id}"), {"name": "v3 put org renamed"}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:500])
        body = response.json()
        self.assertEqual("v3 put org renamed", body["name"])
        self.assertIsNone(body["description"])       # reset to default (None)
        self.assertFalse(body["critical_product"])   # reset to default (False)
        pt.refresh_from_db()
        self.assertIsNone(pt.description)
        self.assertFalse(pt.critical_product)

    def test_put_missing_required_name_is_400(self):
        pt = Product_Type.objects.create(name="v3 put org missing")
        response = self.client.put(
            self.v3_url(f"organizations/{pt.id}"), {"description": "no name"}, format="json",
        )
        self.assertEqual(400, response.status_code)
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_put_unknown_field_is_400(self):
        pt = Product_Type.objects.create(name="v3 put org unknown")
        response = self.client.put(
            self.v3_url(f"organizations/{pt.id}"), {"name": "x", "bogus": 1}, format="json",
        )
        self.assertEqual(400, response.status_code)

    def test_put_unauthorized_is_404(self):
        limited = User.objects.create_user(username="v3_org_put_limited", password="x")  # noqa: S106
        pt = Product_Type.objects.first()
        client = self.token_client(user=limited)
        response = client.put(self.v3_url(f"organizations/{pt.id}"), {"name": "x"}, format="json")
        self.assertEqual(404, response.status_code)

    def test_put_visible_but_not_editable_is_403(self):
        # OS legacy authz can't express view-but-not-edit; fail the edit check while the object stays
        # visible to the admin (§12, OS5 pattern).
        pt = Product_Type.objects.first()
        with mock.patch("dojo.product_type.api_v3.routes.user_has_permission", return_value=False):
            response = self.client.put(self.v3_url(f"organizations/{pt.id}"), {"name": "x"}, format="json")
        self.assertEqual(403, response.status_code, response.content[:300])


class TestApiV3OrganizationsRbac(ApiV3TestCase):

    def setUp(self):
        super().setUp()
        self.limited = User.objects.create_user(username="v3_org_limited", password="x")  # noqa: S106
        # authorized_users M2M targets Dojo_User (the proxy), so the member must be a Dojo_User.
        self.member = Dojo_User.objects.create_user(username="v3_org_member", password="x")  # noqa: S106
        self.pt = Product_Type.objects.first()
        self.pt.authorized_users.add(self.member)

    def test_unauthorized_read_is_404(self):
        client = self.token_client(user=self.limited)
        # Limited user has no organization membership -> empty list, detail 404.
        self.assertEqual(0, self.get_json("organizations", client=client)["count"])
        self.get_json(f"organizations/{self.pt.id}", client=client, expected=404)

    def test_create_without_global_add_is_403(self):
        client = self.token_client(user=self.limited)
        response = client.post(self.v3_url("organizations"), {"name": "v3 nope"}, format="json")
        self.assertEqual(403, response.status_code, response.content[:300])
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_member_can_view_but_delete_is_403(self):
        client = self.token_client(user=self.member)
        # Member can view (200) ...
        self.get_json(f"organizations/{self.pt.id}", client=client)
        # ... but delete is staff-only for non-staff members (legacy model) -> 403 (not 404).
        response = client.delete(self.v3_url(f"organizations/{self.pt.id}"))
        self.assertEqual(403, response.status_code, response.content[:300])
