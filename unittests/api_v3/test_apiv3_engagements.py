"""Engagement CRUD + RBAC + contract tests for API v3 (OS3b)."""
from __future__ import annotations

import datetime

from django.db import connection
from django.test.utils import CaptureQueriesContext

from dojo.engagement.api_v3.schemas import EngagementSlim
from dojo.finding.api_v3 import schemas as finding_schemas
from dojo.models import Dojo_User, Engagement, Product, User

from .base import ApiV3TestCase

_SLIM_KEYS = {
    "id", "name", "product", "product_type", "lead", "status", "engagement_type",
    "target_start", "target_end", "active", "tags", "created", "updated",
}


class TestApiV3EngagementsRelocation(ApiV3TestCase):

    def test_engagement_slim_is_canonical_single_class(self):
        # OS3b relocated EngagementSlim out of the finding module; the finding module now re-exports
        # the one canonical class (is-identity, mirroring the OS3a relocation pattern -- §12).
        self.assertIs(EngagementSlim, finding_schemas.EngagementSlim)


class TestApiV3EngagementsRead(ApiV3TestCase):

    def test_list_envelope_and_slim_shape(self):
        body = self.get_json("engagements")
        self.assertEqual({"count", "next", "previous", "results"}, set(body) - {"meta"})
        self.assertGreater(body["count"], 0)
        row = body["results"][0]
        self.assertEqual(_SLIM_KEYS, set(row))
        self.assertEqual({"id", "name"}, set(row["product"]))
        self.assertEqual({"id", "name"}, set(row["product_type"]))
        self.assertIsInstance(row["tags"], list)

    def test_detail_adds_heavy_fields(self):
        engagement = Engagement.objects.first()
        detail = self.get_json(f"engagements/{engagement.id}")
        for key in ("description", "version", "first_contacted", "threat_model", "deduplication_on_engagement"):
            self.assertIn(key, detail)

    def test_detail_unknown_is_404_problem(self):
        response = self.client.get(self.v3_url("engagements/99999999"))
        self.assertEqual(404, response.status_code)
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_expand_product_inlines_slim(self):
        row = self.get_json("engagements", data={"expand": "product"})["results"][0]
        self.assertIn("description", row["product"])
        self.assertIn("lifecycle", row["product"])

    def test_expand_lead_and_product_type(self):
        eng = Engagement.objects.exclude(lead__isnull=True).first()
        if eng is None:
            eng = Engagement.objects.first()
            eng.lead = self.admin
            eng.save()
        row = self.get_json("engagements", data={"expand": "lead,product_type", "id__in": eng.id})["results"][0]
        self.assertIn("username", row["lead"])
        self.assertIn("critical_product", row["product_type"])

    def test_expand_unknown_relation_is_400(self):
        self.get_json("engagements", data={"expand": "not_a_relation"}, expected=400)


class TestApiV3EngagementsFilters(ApiV3TestCase):

    def test_filter_product(self):
        product_id = Engagement.objects.first().product_id
        body = self.get_json("engagements", data={"product": product_id, "limit": 250})
        self.assertGreater(body["count"], 0)
        for row in body["results"]:
            self.assertEqual(product_id, row["product"]["id"])

    def test_filter_status(self):
        eng = Engagement.objects.first()
        body = self.get_json("engagements", data={"status": eng.status, "limit": 250})
        for row in body["results"]:
            self.assertEqual(eng.status, row["status"])

    def test_ordering_by_id(self):
        ids = [r["id"] for r in self.get_json("engagements", data={"o": "id", "limit": 250})["results"]]
        self.assertEqual(ids, sorted(ids))

    def test_unknown_filter_param_is_400(self):
        self.get_json("engagements", data={"not_a_filter": "x"}, expected=400)


class TestApiV3EngagementsPagination(ApiV3TestCase):

    def test_limit_next_previous(self):
        body = self.get_json("engagements", data={"limit": 2, "offset": 2})
        self.assertLessEqual(len(body["results"]), 2)
        self.assertIsNotNone(body["previous"])


class TestApiV3EngagementsQueryCount(ApiV3TestCase):

    def _bulk(self, count: int, start: int) -> None:
        product = Product.objects.first()
        day = datetime.date(2024, 1, 1)
        Engagement.objects.bulk_create([
            Engagement(name=f"qcount engagement {start + i}", product=product, target_start=day, target_end=day)
            for i in range(count)
        ])

    def _query_count(self, params: dict) -> int:
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(self.v3_url("engagements"), params)
            self.assertEqual(200, response.status_code, response.content[:500])
        return len(ctx.captured_queries)

    def test_query_count_is_independent_of_row_count(self):
        self._bulk(10, 0)
        first = self._query_count({"limit": 250})
        first_expand = self._query_count({"limit": 250, "expand": "product.product_type"})
        self._bulk(90, 100)
        second = self._query_count({"limit": 250})
        second_expand = self._query_count({"limit": 250, "expand": "product.product_type"})
        self.assertEqual(first, second, f"query count grew (no expand): {first} -> {second}")
        self.assertEqual(first_expand, second_expand, f"query count grew (expand): {first_expand} -> {second_expand}")


class TestApiV3EngagementsWrite(ApiV3TestCase):

    def test_create_happy_path(self):
        product = Product.objects.first()
        response = self.client.post(
            self.v3_url("engagements"),
            {"name": "v3 created engagement", "product": product.id,
             "target_start": "2024-01-01", "target_end": "2024-02-01",
             "status": "In Progress", "tags": ["v3"]},
            format="json",
        )
        self.assertEqual(201, response.status_code, response.content[:500])
        body = response.json()
        self.assertEqual("v3 created engagement", body["name"])
        self.assertEqual(product.id, body["product"]["id"])
        created = Engagement.objects.get(name="v3 created engagement")
        self.assertEqual({"v3"}, {t.name for t in created.tags.all()})

    def test_create_target_start_after_end_is_400(self):
        product = Product.objects.first()
        response = self.client.post(
            self.v3_url("engagements"),
            {"name": "bad dates", "product": product.id,
             "target_start": "2024-02-01", "target_end": "2024-01-01"},
            format="json",
        )
        self.assertEqual(400, response.status_code)
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_create_missing_required_is_400(self):
        response = self.client.post(self.v3_url("engagements"), {"name": "no product"}, format="json")
        self.assertEqual(400, response.status_code)

    def test_create_unknown_field_is_400(self):
        product = Product.objects.first()
        response = self.client.post(
            self.v3_url("engagements"),
            {"product": product.id, "target_start": "2024-01-01", "target_end": "2024-02-01", "bogus": 1},
            format="json",
        )
        self.assertEqual(400, response.status_code)

    def test_create_nonexistent_product_is_404(self):
        response = self.client.post(
            self.v3_url("engagements"),
            {"product": 99999999, "target_start": "2024-01-01", "target_end": "2024-02-01"},
            format="json",
        )
        self.assertEqual(404, response.status_code)

    def test_patch_partial_update(self):
        product = Product.objects.first()
        eng = Engagement.objects.create(
            name="v3 patch engagement", product=product,
            target_start=datetime.date(2024, 1, 1), target_end=datetime.date(2024, 2, 1),
        )
        response = self.client.patch(
            self.v3_url(f"engagements/{eng.id}"), {"name": "renamed"}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:500])
        eng.refresh_from_db()
        self.assertEqual("renamed", eng.name)

    def test_delete(self):
        product = Product.objects.first()
        eng = Engagement.objects.create(
            name="v3 delete engagement", product=product,
            target_start=datetime.date(2024, 1, 1), target_end=datetime.date(2024, 2, 1),
        )
        response = self.client.delete(self.v3_url(f"engagements/{eng.id}"))
        self.assertEqual(204, response.status_code)
        self.assertFalse(Engagement.objects.filter(pk=eng.id).exists())


class TestApiV3EngagementsRbac(ApiV3TestCase):

    def setUp(self):
        super().setUp()
        self.limited = User.objects.create_user(username="v3_eng_limited", password="x")  # noqa: S106
        self.member = Dojo_User.objects.create_user(username="v3_eng_member", password="x")  # noqa: S106
        self.engagement = Engagement.objects.first()
        self.product = self.engagement.product
        self.product.authorized_users.add(self.member)

    def test_unauthorized_read_is_404(self):
        client = self.token_client(user=self.limited)
        self.assertEqual(0, self.get_json("engagements", client=client)["count"])
        self.get_json(f"engagements/{self.engagement.id}", client=client, expected=404)

    def test_create_without_product_add_is_403(self):
        client = self.token_client(user=self.limited)
        response = client.post(
            self.v3_url("engagements"),
            {"product": self.product.id, "target_start": "2024-01-01", "target_end": "2024-02-01"},
            format="json",
        )
        self.assertEqual(403, response.status_code, response.content[:300])
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_member_can_view_but_delete_is_403(self):
        # OS legacy RBAC: membership grants view+edit+add, but delete is staff-only -- so the
        # "authorized-to-see-but-not-modify" 403 is demonstrated on delete (§12).
        client = self.token_client(user=self.member)
        self.get_json(f"engagements/{self.engagement.id}", client=client)
        response = client.delete(self.v3_url(f"engagements/{self.engagement.id}"))
        self.assertEqual(403, response.status_code, response.content[:300])
