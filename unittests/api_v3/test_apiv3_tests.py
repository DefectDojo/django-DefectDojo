"""Test (scan run) CRUD + RBAC + contract tests for API v3 (OS3b)."""
from __future__ import annotations

import datetime

from django.db import connection
from django.test.utils import CaptureQueriesContext

from dojo.finding.api_v3 import schemas as finding_schemas
from dojo.models import Dojo_User, Engagement, Test, Test_Type, User
from dojo.test.api_v3.schemas import EnvironmentSlim, TestSlim, TestTypeSlim

from .base import ApiV3TestCase

_SLIM_KEYS = {
    "id", "name", "test_type", "engagement", "asset", "organization", "environment",
    "lead", "target_start", "target_end", "percent_complete", "tags", "created", "updated",
}


class TestApiV3TestsRelocation(ApiV3TestCase):

    def test_test_slims_are_canonical_single_classes(self):
        # OS3b relocated TestSlim/TestTypeSlim/EnvironmentSlim out of the finding module; the finding
        # module now re-exports the one canonical class each (is-identity -- §12 relocation pattern).
        self.assertIs(TestSlim, finding_schemas.TestSlim)
        self.assertIs(TestTypeSlim, finding_schemas.TestTypeSlim)
        self.assertIs(EnvironmentSlim, finding_schemas.EnvironmentSlim)


class TestApiV3TestsRead(ApiV3TestCase):

    def test_list_envelope_and_slim_shape(self):
        body = self.get_json("tests")
        self.assertEqual({"count", "next", "previous", "results"}, set(body) - {"meta"})
        self.assertGreater(body["count"], 0)
        row = body["results"][0]
        self.assertEqual(_SLIM_KEYS, set(row))
        self.assertEqual({"id", "name"}, set(row["test_type"]))
        self.assertEqual({"id", "name"}, set(row["engagement"]))
        self.assertIsInstance(row["tags"], list)

    def test_detail_adds_heavy_fields(self):
        test = Test.objects.first()
        detail = self.get_json(f"tests/{test.id}")
        for key in ("description", "scan_type", "version", "build_id", "commit_hash", "branch_tag"):
            self.assertIn(key, detail)

    def test_detail_unknown_is_404_problem(self):
        response = self.client.get(self.v3_url("tests/99999999"))
        self.assertEqual(404, response.status_code)
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_expand_engagement_and_test_type(self):
        row = self.get_json("tests", data={"expand": "engagement,test_type"})["results"][0]
        self.assertIn("status", row["engagement"])
        self.assertIn("active", row["test_type"])

    def test_expand_unknown_relation_is_400(self):
        self.get_json("tests", data={"expand": "not_a_relation"}, expected=400)


class TestApiV3TestsFilters(ApiV3TestCase):

    def test_filter_engagement(self):
        engagement_id = Test.objects.first().engagement_id
        body = self.get_json("tests", data={"engagement": engagement_id, "limit": 250})
        self.assertGreater(body["count"], 0)
        for row in body["results"]:
            self.assertEqual(engagement_id, row["engagement"]["id"])

    def test_filter_test_type(self):
        tt_id = Test.objects.first().test_type_id
        body = self.get_json("tests", data={"test_type": tt_id, "limit": 250})
        for row in body["results"]:
            self.assertEqual(tt_id, row["test_type"]["id"])

    def test_ordering_by_id(self):
        ids = [r["id"] for r in self.get_json("tests", data={"o": "id", "limit": 250})["results"]]
        self.assertEqual(ids, sorted(ids))

    def test_unknown_filter_param_is_400(self):
        self.get_json("tests", data={"not_a_filter": "x"}, expected=400)


class TestApiV3TestsPagination(ApiV3TestCase):

    def test_limit_next_previous(self):
        body = self.get_json("tests", data={"limit": 2, "offset": 2})
        self.assertLessEqual(len(body["results"]), 2)
        self.assertIsNotNone(body["previous"])


class TestApiV3TestsQueryCount(ApiV3TestCase):

    def _bulk(self, count: int, start: int) -> None:
        engagement = Engagement.objects.first()
        test_type = Test_Type.objects.first()
        now = datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC)
        Test.objects.bulk_create([
            Test(engagement=engagement, test_type=test_type, target_start=now, target_end=now)
            for _ in range(count)
        ])

    def _query_count(self, params: dict) -> int:
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(self.v3_url("tests"), params)
            self.assertEqual(200, response.status_code, response.content[:500])
        return len(ctx.captured_queries)

    def test_query_count_is_independent_of_row_count(self):
        self._bulk(10, 0)
        first = self._query_count({"limit": 250})
        first_expand = self._query_count({"limit": 250, "expand": "engagement.asset,test_type"})
        self._bulk(90, 100)
        second = self._query_count({"limit": 250})
        second_expand = self._query_count({"limit": 250, "expand": "engagement.asset,test_type"})
        self.assertEqual(first, second, f"query count grew (no expand): {first} -> {second}")
        self.assertEqual(first_expand, second_expand, f"query count grew (expand): {first_expand} -> {second_expand}")


class TestApiV3TestsWrite(ApiV3TestCase):

    def test_create_happy_path(self):
        engagement = Engagement.objects.first()
        test_type = Test_Type.objects.first()
        response = self.client.post(
            self.v3_url("tests"),
            {"engagement": engagement.id, "test_type": test_type.id,
             "target_start": "2024-01-01T00:00:00Z", "target_end": "2024-01-02T00:00:00Z",
             "title": "v3 created test", "tags": ["v3"]},
            format="json",
        )
        self.assertEqual(201, response.status_code, response.content[:500])
        body = response.json()
        self.assertEqual("v3 created test", body["name"])
        self.assertEqual(engagement.id, body["engagement"]["id"])
        created = Test.objects.get(title="v3 created test")
        self.assertEqual({"v3"}, {t.name for t in created.tags.all()})

    def test_create_bad_test_type_is_400(self):
        engagement = Engagement.objects.first()
        response = self.client.post(
            self.v3_url("tests"),
            {"engagement": engagement.id, "test_type": 99999999,
             "target_start": "2024-01-01T00:00:00Z", "target_end": "2024-01-02T00:00:00Z"},
            format="json",
        )
        self.assertEqual(400, response.status_code)

    def test_create_missing_required_is_400(self):
        response = self.client.post(self.v3_url("tests"), {"title": "no engagement"}, format="json")
        self.assertEqual(400, response.status_code)

    def test_create_unknown_field_is_400(self):
        engagement = Engagement.objects.first()
        test_type = Test_Type.objects.first()
        response = self.client.post(
            self.v3_url("tests"),
            {"engagement": engagement.id, "test_type": test_type.id,
             "target_start": "2024-01-01T00:00:00Z", "target_end": "2024-01-02T00:00:00Z", "bogus": 1},
            format="json",
        )
        self.assertEqual(400, response.status_code)

    def test_create_nonexistent_engagement_is_404(self):
        test_type = Test_Type.objects.first()
        response = self.client.post(
            self.v3_url("tests"),
            {"engagement": 99999999, "test_type": test_type.id,
             "target_start": "2024-01-01T00:00:00Z", "target_end": "2024-01-02T00:00:00Z"},
            format="json",
        )
        self.assertEqual(404, response.status_code)

    def test_patch_partial_update(self):
        test = Test.objects.first()
        response = self.client.patch(
            self.v3_url(f"tests/{test.id}"), {"title": "renamed test"}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:500])
        test.refresh_from_db()
        self.assertEqual("renamed test", test.title)

    def test_patch_engagement_is_rejected_as_unknown_field(self):
        # engagement is editable=False on the model -> not part of the update schema (mirrors v2).
        test = Test.objects.first()
        other = Engagement.objects.exclude(pk=test.engagement_id).first()
        response = self.client.patch(
            self.v3_url(f"tests/{test.id}"), {"engagement": other.id}, format="json",
        )
        self.assertEqual(400, response.status_code)

    def test_delete(self):
        engagement = Engagement.objects.first()
        test_type = Test_Type.objects.first()
        test = Test.objects.create(
            engagement=engagement, test_type=test_type,
            target_start=datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC),
            target_end=datetime.datetime(2024, 1, 2, tzinfo=datetime.UTC),
        )
        response = self.client.delete(self.v3_url(f"tests/{test.id}"))
        self.assertEqual(204, response.status_code)
        self.assertFalse(Test.objects.filter(pk=test.id).exists())


class TestApiV3TestsRbac(ApiV3TestCase):

    def setUp(self):
        super().setUp()
        self.limited = User.objects.create_user(username="v3_test_limited", password="x")  # noqa: S106
        self.member = Dojo_User.objects.create_user(username="v3_test_member", password="x")  # noqa: S106
        self.test = Test.objects.first()
        self.product = self.test.engagement.product
        self.product.authorized_users.add(self.member)

    def test_unauthorized_read_is_404(self):
        client = self.token_client(user=self.limited)
        self.assertEqual(0, self.get_json("tests", client=client)["count"])
        self.get_json(f"tests/{self.test.id}", client=client, expected=404)

    def test_create_without_engagement_add_is_403(self):
        client = self.token_client(user=self.limited)
        test_type = Test_Type.objects.first()
        response = client.post(
            self.v3_url("tests"),
            {"engagement": self.test.engagement_id, "test_type": test_type.id,
             "target_start": "2024-01-01T00:00:00Z", "target_end": "2024-01-02T00:00:00Z"},
            format="json",
        )
        self.assertEqual(403, response.status_code, response.content[:300])
        self.assertEqual("application/problem+json", response["Content-Type"])

    def test_member_can_view_but_delete_is_403(self):
        # OS legacy RBAC: membership grants view+edit+add; delete is staff-only (§12).
        client = self.token_client(user=self.member)
        self.get_json(f"tests/{self.test.id}", client=client)
        response = client.delete(self.v3_url(f"tests/{self.test.id}"))
        self.assertEqual(403, response.status_code, response.content[:300])
