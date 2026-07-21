"""
Test-detail dedupe/matching-policy read fields for API v3 (ports ``test_apiv2_test_dedupe_policy.py``).

v3's Test detail exposes the effective finding-matching policy -- ``deduplication_algorithm`` and
``hash_code_fields`` -- as READ-ONLY computed fields (§4.5, §9.1). They reuse the v2 helper
verbatim: the ``Test.deduplication_algorithm`` / ``Test.hash_code_fields`` model properties
(``dojo/test/models.py``), the settings-driven per-scanner lookup the v2 ``TestSerializer`` reads.
The values mirror the per-scanner settings, so the assertions read the live settings dicts
dynamically (like the v2 test) rather than hardcoding the current config.

Deliberate deviation, hardened over v2 (§12): the fields are NOT on any write schema (all
``extra="forbid"``), so a PATCH/PUT that supplies either is a **400** problem+json -- v2 silently
*ignores* writes to them. Silent-ignore is exactly the failure mode v3 rejects everywhere (the same
principle as unknown filter/expand/fields params).
"""
from __future__ import annotations

import csv
import datetime
import io

from django.conf import settings
from django.db import connection
from django.test.utils import CaptureQueriesContext

from dojo.api_v3.expand import plan_list_fields
from dojo.models import Engagement, Test, Test_Type
from dojo.test.api_v3.schemas import TestDetail, TestSlim

from .base import ApiV3TestCase

# Two scan types with genuinely different policies (mirrors the v2 test's per-scanner assertions),
# plus a made-up scan type absent from both settings dicts for the default-fallback case.
_HASH_CODE_SCAN = "ZAP Scan"                    # -> hash_code + ["title", "cwe", "severity"]
_UNIQUE_ID_SCAN = "Checkmarx Scan detailed"     # -> unique_id_from_tool + no hashcode fields (None)
_DEFAULT_SCAN = "V3 Nonexistent Custom Scan Type"  # -> legacy (fallback) + None


def _now() -> datetime.datetime:
    return datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC)


class _DedupePolicyBase(ApiV3TestCase):

    def _make_test(self, scan_type: str) -> Test:
        # test_type.name is what the model property checks first, then scan_type; set both equal (the
        # real-world case for an imported test, and what the v2 test relied on).
        engagement = Engagement.objects.first()
        test_type, _ = Test_Type.objects.get_or_create(name=scan_type)
        return Test.objects.create(
            engagement=engagement, test_type=test_type, scan_type=scan_type,
            target_start=_now(), target_end=_now(),
        )


class TestApiV3DedupePolicyRead(_DedupePolicyBase):

    """The Test detail exposes the effective matching policy, resolved from the per-scanner settings."""

    def _assert_policy(self, scan_type: str) -> dict:
        test = self._make_test(scan_type)
        data = self.get_json(f"tests/{test.id}")
        # Mirror v2: assert against the live settings so a config change never silently passes.
        expected_algorithm = settings.DEDUPLICATION_ALGORITHM_PER_PARSER.get(
            scan_type, settings.DEDUPE_ALGO_LEGACY)
        expected_fields = settings.HASHCODE_FIELDS_PER_SCANNER.get(scan_type)
        self.assertIn("deduplication_algorithm", data)
        self.assertIn("hash_code_fields", data)
        self.assertEqual(expected_algorithm, data["deduplication_algorithm"])
        self.assertEqual(expected_fields, data["hash_code_fields"])
        return data

    def test_hash_code_scan_type_exposes_algorithm_and_fields(self):
        data = self._assert_policy(_HASH_CODE_SCAN)
        # Concrete expectation documenting the "hash_code" policy for this scanner.
        self.assertEqual("hash_code", data["deduplication_algorithm"])
        self.assertEqual(["title", "cwe", "severity"], data["hash_code_fields"])

    def test_unique_id_scan_type_has_a_different_policy(self):
        data = self._assert_policy(_UNIQUE_ID_SCAN)
        # A genuinely different policy from _HASH_CODE_SCAN: unique_id_from_tool, no hashcode fields.
        self.assertEqual("unique_id_from_tool", data["deduplication_algorithm"])
        self.assertIsNone(data["hash_code_fields"])

    def test_two_scan_types_have_distinct_algorithms(self):
        # Proves the field is genuinely computed per scan type, not a constant.
        hash_code = self.get_json(f"tests/{self._make_test(_HASH_CODE_SCAN).id}")
        unique_id = self.get_json(f"tests/{self._make_test(_UNIQUE_ID_SCAN).id}")
        self.assertNotEqual(
            hash_code["deduplication_algorithm"], unique_id["deduplication_algorithm"])

    def test_unconfigured_scan_type_falls_back_to_legacy(self):
        data = self._assert_policy(_DEFAULT_SCAN)
        # The documented default when a scan type has no per-scanner configuration.
        self.assertEqual(settings.DEDUPE_ALGO_LEGACY, data["deduplication_algorithm"])
        self.assertIsNone(data["hash_code_fields"])

    def test_detail_computes_policy_without_extra_queries(self):
        # The resolvers read only test_type (already select_related in TestSlim.SELECT_RELATED) and
        # scan_type (a concrete column, never deferred on a detail fetch) -> zero extra queries. Uses
        # the detail route's exact select_related shape (Test.objects stands in for the authorized
        # queryset, which resolves the user via crum -- unset outside an HTTP request).
        test = self._make_test(_HASH_CODE_SCAN)
        obj = Test.objects.select_related(*TestDetail.SELECT_RELATED).get(pk=test.id)
        with self.assertNumQueries(0):
            self.assertEqual("hash_code", obj.deduplication_algorithm)
            self.assertEqual(["title", "cwe", "severity"], obj.hash_code_fields)


class TestApiV3DedupePolicyWriteRejected(_DedupePolicyBase):

    """v3 REJECTS writes to the policy fields (400) where v2 silently IGNORES them (§12)."""

    def _assert_unknown_field_400(self, response, field: str) -> None:
        self.assertEqual(400, response.status_code, response.content[:400])
        self.assertEqual("application/problem+json", response["Content-Type"])
        # The rejected field is named in the problem body (unknown-field, not a generic 400).
        self.assertIn(field.encode(), response.content)

    def test_patch_deduplication_algorithm_is_400(self):
        test = self._make_test(_HASH_CODE_SCAN)
        response = self.client.patch(
            self.v3_url(f"tests/{test.id}"), {"deduplication_algorithm": "hash_code"}, format="json")
        self._assert_unknown_field_400(response, "deduplication_algorithm")

    def test_patch_hash_code_fields_is_400(self):
        test = self._make_test(_HASH_CODE_SCAN)
        response = self.client.patch(
            self.v3_url(f"tests/{test.id}"), {"hash_code_fields": ["title"]}, format="json")
        self._assert_unknown_field_400(response, "hash_code_fields")

    def test_put_deduplication_algorithm_is_400(self):
        test = self._make_test(_HASH_CODE_SCAN)
        payload = {
            "test_type": test.test_type_id,
            "target_start": "2024-01-01T00:00:00Z",
            "target_end": "2024-01-02T00:00:00Z",
            "deduplication_algorithm": "hash_code",
        }
        response = self.client.put(self.v3_url(f"tests/{test.id}"), payload, format="json")
        self._assert_unknown_field_400(response, "deduplication_algorithm")

    def test_put_hash_code_fields_is_400(self):
        test = self._make_test(_HASH_CODE_SCAN)
        payload = {
            "test_type": test.test_type_id,
            "target_start": "2024-01-01T00:00:00Z",
            "target_end": "2024-01-02T00:00:00Z",
            "hash_code_fields": ["title"],
        }
        response = self.client.put(self.v3_url(f"tests/{test.id}"), payload, format="json")
        self._assert_unknown_field_400(response, "hash_code_fields")

    def test_reject_is_atomic_v3_hardens_where_v2_ignores(self):
        # The exact v2 scenario (test_matching_policy_ignored_on_write): a PATCH mixing the read-only
        # policy fields with a real field. v2 returns 200 and silently ignores the policy fields; v3
        # rejects the whole request (400) and applies nothing -- the deliberate reject-vs-ignore
        # deviation. The description must be unchanged after the rejection.
        test = self._make_test(_HASH_CODE_SCAN)
        original_description = test.description
        response = self.client.patch(
            self.v3_url(f"tests/{test.id}"),
            {"deduplication_algorithm": "hash_code", "hash_code_fields": ["title"], "description": "updated"},
            format="json",
        )
        self.assertEqual(400, response.status_code, response.content[:400])
        self.assertEqual("application/problem+json", response["Content-Type"])
        test.refresh_from_db()
        self.assertEqual(original_description, test.description)


class TestApiV3DedupePolicyFieldsOptUp(_DedupePolicyBase):

    """``?fields=`` opt-up on a LIST: the computed detail field serializes via the detail resolver."""

    def _bulk(self, count: int) -> None:
        engagement = Engagement.objects.first()
        test_type, _ = Test_Type.objects.get_or_create(name=_HASH_CODE_SCAN)
        Test.objects.bulk_create([
            Test(engagement=engagement, test_type=test_type, scan_type=_HASH_CODE_SCAN,
                 target_start=_now(), target_end=_now())
            for _ in range(count)
        ])

    def _query_count(self, params: dict) -> int:
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(self.v3_url("tests"), params)
            self.assertEqual(200, response.status_code, response.content[:500])
        return len(ctx.captured_queries)

    def test_not_present_on_default_list_row(self):
        # The default (no ?fields=) list is the slim shape -- the detail-only policy fields are absent.
        self._make_test(_HASH_CODE_SCAN)
        row = self.get_json("tests", data={"limit": 250})["results"][0]
        self.assertNotIn("deduplication_algorithm", row)
        self.assertNotIn("hash_code_fields", row)

    def test_fields_opt_up_returns_the_computed_field(self):
        self._make_test(_HASH_CODE_SCAN)
        body = self.get_json("tests", data={"fields": "id,name,deduplication_algorithm", "limit": 250})
        row = body["results"][0]
        self.assertEqual({"id", "name", "deduplication_algorithm"}, set(row))
        self.assertIsInstance(row["deduplication_algorithm"], str)

    def test_fields_opt_up_value_matches_detail(self):
        test = self._make_test(_HASH_CODE_SCAN)
        row = next(
            r for r in self.get_json(
                "tests", data={"fields": "id,deduplication_algorithm,hash_code_fields", "limit": 250},
            )["results"]
            if r["id"] == test.id
        )
        self.assertEqual("hash_code", row["deduplication_algorithm"])
        self.assertEqual(["title", "cwe", "severity"], row["hash_code_fields"])

    def test_computed_fields_never_enter_the_defer_set(self):
        # Kernel-level: the policy fields are resolver-backed (not concrete columns), so they are
        # never defer candidates; requesting deduplication_algorithm un-defers exactly ``scan_type``
        # (the concrete column its resolver reads) via TestDetail.DETAIL_FIELD_COLUMNS.
        default_plan = plan_list_fields(TestSlim, TestDetail, None)
        self.assertIn("scan_type", default_plan.defer)  # deferred by default
        self.assertNotIn("deduplication_algorithm", default_plan.defer)
        self.assertNotIn("hash_code_fields", default_plan.defer)

        opt_up = plan_list_fields(TestSlim, TestDetail, {"id", "name", "deduplication_algorithm"})
        self.assertIn("deduplication_algorithm", opt_up.detail_extra)
        self.assertNotIn("scan_type", opt_up.defer)  # un-deferred: the resolver reads it
        self.assertNotIn("deduplication_algorithm", opt_up.defer)

    def test_query_count_is_independent_of_row_count(self):
        # GET /tests?fields=id,name,deduplication_algorithm must stay constant-query (no per-row lazy
        # load of the deferred scan_type column). This is the headline claim for the opt-up.
        self._bulk(10)
        first = self._query_count({"limit": 250, "fields": "id,name,deduplication_algorithm"})
        self._bulk(90)
        second = self._query_count({"limit": 250, "fields": "id,name,deduplication_algorithm"})
        self.assertEqual(first, second, f"query count grew with rows: {first} -> {second}")

    def test_csv_export_flattens_policy_columns(self):
        test = self._make_test(_HASH_CODE_SCAN)
        response = self.client.get(
            self.v3_url("tests/export.csv"),
            {"fields": "id,name,deduplication_algorithm,hash_code_fields"},
        )
        self.assertEqual(200, response.status_code)
        rows = list(csv.reader(io.StringIO(b"".join(response.streaming_content).decode("utf-8"))))
        header = rows[0]
        self.assertIn("deduplication_algorithm", header)
        self.assertIn("hash_code_fields", header)  # a list field -> one semicolon-joined column
        indexed = {r[header.index("id")]: dict(zip(header, r, strict=True)) for r in rows[1:]}
        row = indexed[str(test.id)]
        self.assertEqual("hash_code", row["deduplication_algorithm"])
        self.assertEqual("title;cwe;severity", row["hash_code_fields"])
