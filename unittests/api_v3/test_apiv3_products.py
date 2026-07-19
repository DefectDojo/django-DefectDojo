"""Product CRUD + RBAC + contract tests for API v3 (OS3a)."""
from __future__ import annotations

from django.db import connection
from django.test.utils import CaptureQueriesContext

from dojo.models import Dojo_User, Product, Product_Type, User

from .base import ApiV3TestCase

_SLIM_KEYS = {"id", "name", "description", "product_type", "lifecycle", "tags", "created", "updated"}


class TestApiV3ProductsRead(ApiV3TestCase):

    def test_list_envelope_and_slim_shape(self):
        body = self.get_json("products")
        self.assertEqual({"count", "next", "previous", "results"}, set(body) - {"meta"})
        self.assertGreater(body["count"], 0)
        row = body["results"][0]
        self.assertEqual(_SLIM_KEYS, set(row))
        self.assertEqual({"id", "name"}, set(row["product_type"]))
        self.assertIsInstance(row["tags"], list)

    def test_detail_adds_heavy_fields(self):
        product = Product.objects.first()
        detail = self.get_json(f"products/{product.id}")
        for key in ("business_criticality", "platform", "origin", "product_manager", "technical_contact", "team_manager"):
            self.assertIn(key, detail)

    def test_detail_unknown_is_404_problem(self):
        response = self.client.get(self.v3_url("products/99999999"))
        self.assertEqual(404, response.status_code)
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_expand_product_type_inlines_slim(self):
        row = self.get_json("products", data={"expand": "product_type"})["results"][0]
        # ref swapped for the product_type slim (carries description, timestamps, not just id/name).
        self.assertIn("description", row["product_type"])
        self.assertIn("critical_product", row["product_type"])

    def test_expand_unknown_relation_is_400(self):
        self.get_json("products", data={"expand": "not_a_relation"}, expected=400)


class TestApiV3ProductsFilters(ApiV3TestCase):

    def test_filter_product_type(self):
        pt_id = Product.objects.first().prod_type_id
        body = self.get_json("products", data={"product_type": pt_id, "limit": 250})
        self.assertGreater(body["count"], 0)
        for row in body["results"]:
            self.assertEqual(pt_id, row["product_type"]["id"])

    def test_filter_name_icontains(self):
        name = Product.objects.first().name
        body = self.get_json("products", data={"name__icontains": name[:5]})
        self.assertGreater(body["count"], 0)

    def test_ordering_by_name(self):
        names = [r["name"] for r in self.get_json("products", data={"o": "name", "limit": 250})["results"]]
        self.assertEqual(names, sorted(names))

    def test_unknown_filter_param_is_400(self):
        self.get_json("products", data={"not_a_filter": "x"}, expected=400)


class TestApiV3ProductsPagination(ApiV3TestCase):

    def test_limit_next_previous(self):
        body = self.get_json("products", data={"limit": 2, "offset": 2})
        self.assertLessEqual(len(body["results"]), 2)
        self.assertIsNotNone(body["previous"])


class TestApiV3ProductsQueryCount(ApiV3TestCase):

    def _bulk(self, count: int, start: int) -> None:
        pt = Product_Type.objects.first()
        Product.objects.bulk_create([
            Product(name=f"qcount product {start + i}", description="x", prod_type=pt, sla_configuration_id=1)
            for i in range(count)
        ])

    def _query_count(self, params: dict) -> int:
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(self.v3_url("products"), params)
            self.assertEqual(200, response.status_code, response.content[:500])
        return len(ctx.captured_queries)

    def test_query_count_is_independent_of_row_count(self):
        self._bulk(10, 0)
        first = self._query_count({"limit": 250})
        first_expand = self._query_count({"limit": 250, "expand": "product_type"})
        self._bulk(90, 100)
        second = self._query_count({"limit": 250})
        second_expand = self._query_count({"limit": 250, "expand": "product_type"})
        self.assertEqual(first, second, f"query count grew (no expand): {first} -> {second}")
        self.assertEqual(first_expand, second_expand, f"query count grew (expand): {first_expand} -> {second_expand}")


class TestApiV3ProductsWrite(ApiV3TestCase):

    def test_create_happy_path(self):
        pt = Product_Type.objects.first()
        response = self.client.post(
            self.v3_url("products"),
            {"name": "v3 created product", "description": "made by v3", "prod_type": pt.id,
             "lifecycle": "production", "tags": ["pci", "v3"]},
            format="json",
        )
        self.assertEqual(201, response.status_code, response.content[:500])
        body = response.json()
        self.assertEqual("v3 created product", body["name"])
        self.assertEqual(pt.id, body["product_type"]["id"])
        created = Product.objects.get(name="v3 created product")
        self.assertEqual("production", created.lifecycle)
        self.assertEqual({"pci", "v3"}, {t.name for t in created.tags.all()})

    def test_create_missing_required_is_400(self):
        response = self.client.post(self.v3_url("products"), {"name": "no prodtype"}, format="json")
        self.assertEqual(400, response.status_code)
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_create_unknown_field_is_400(self):
        pt = Product_Type.objects.first()
        response = self.client.post(
            self.v3_url("products"),
            {"name": "x", "description": "y", "prod_type": pt.id, "bogus": 1},
            format="json",
        )
        self.assertEqual(400, response.status_code)

    def test_create_nonexistent_prod_type_is_404(self):
        response = self.client.post(
            self.v3_url("products"),
            {"name": "orphan", "description": "y", "prod_type": 99999999},
            format="json",
        )
        self.assertEqual(404, response.status_code)

    def test_patch_partial_update(self):
        pt = Product_Type.objects.first()
        product = Product.objects.create(name="v3 patch product", description="old", prod_type=pt, sla_configuration_id=1)
        response = self.client.patch(
            self.v3_url(f"products/{product.id}"), {"description": "new"}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:500])
        product.refresh_from_db()
        self.assertEqual("new", product.description)
        self.assertEqual("v3 patch product", product.name)

    def test_delete(self):
        pt = Product_Type.objects.first()
        product = Product.objects.create(name="v3 delete product", description="d", prod_type=pt, sla_configuration_id=1)
        response = self.client.delete(self.v3_url(f"products/{product.id}"))
        self.assertEqual(204, response.status_code)
        self.assertFalse(Product.objects.filter(pk=product.id).exists())


class TestApiV3ProductsRbac(ApiV3TestCase):

    def setUp(self):
        super().setUp()
        self.limited = User.objects.create_user(username="v3_prod_limited", password="x")  # noqa: S106
        # authorized_users M2M targets Dojo_User (the proxy), so the member must be a Dojo_User.
        self.member = Dojo_User.objects.create_user(username="v3_prod_member", password="x")  # noqa: S106
        self.product = Product.objects.first()
        self.product.authorized_users.add(self.member)

    def test_unauthorized_read_is_404(self):
        client = self.token_client(user=self.limited)
        self.assertEqual(0, self.get_json("products", client=client)["count"])
        self.get_json(f"products/{self.product.id}", client=client, expected=404)

    def test_create_without_prod_type_add_is_403(self):
        client = self.token_client(user=self.limited)
        response = client.post(
            self.v3_url("products"),
            {"name": "v3 rbac nope", "description": "d", "prod_type": self.product.prod_type_id},
            format="json",
        )
        self.assertEqual(403, response.status_code, response.content[:300])
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_member_can_view_but_delete_is_403(self):
        client = self.token_client(user=self.member)
        self.get_json(f"products/{self.product.id}", client=client)
        response = client.delete(self.v3_url(f"products/{self.product.id}"))
        self.assertEqual(403, response.status_code, response.content[:300])
