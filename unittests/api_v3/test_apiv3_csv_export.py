"""
CSV export contract tests for API v3 (§4.15, D6 "one filter contract, many projections").

``GET /<resource>/export.csv`` takes the identical filter contract as the list (filters, ``o=``,
``q=``, ``?fields=`` incl. the detail opt-up) and streams the whole filtered, authorized set as CSV.
No pagination/expand/include (those 400). Rows are flattened generically: refs -> ``<key>_id`` /
``<key>_name`` (+ ``_type`` for location refs), ``tags`` -> a semicolon-joined column, datetimes
ISO-8601 ``Z``. The filtered count is capped (``API_V3_EXPORT_MAX_ROWS``); over-cap is a 400, never
a silent truncation. Cell values that could be read as spreadsheet formulas are quote-prefixed.
"""
from __future__ import annotations

import csv
import io
import json

from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from dojo.api_v3.csv_export import _harden  # noqa: PLC2701 -- focused kernel unit test of the injection guard
from dojo.models import Dojo_User, Engagement, Finding, Product, Product_Type, Test, Test_Type

from .base import ApiV3TestCase

# The flattened finding CSV header for the default (no ?fields=) export: slim shape with refs fanned
# out into id/name pairs and tags as one joined column (§4.15).
_FINDING_DEFAULT_COLUMNS = [
    "id", "title", "severity", "active", "verified", "false_p", "duplicate", "risk_accepted",
    "out_of_scope", "is_mitigated", "date", "cwe",
    "test_id", "test_name", "engagement_id", "engagement_name", "asset_id", "asset_name",
    "organization_id", "organization_name", "reporter_id", "reporter_name",
    "locations_count", "tags", "created", "updated",
]


class _CsvExportTestCase(ApiV3TestCase):

    """Shared helpers: fetch an export, parse the streamed CSV, index rows by id."""

    def _get(self, path: str, *, client=None, **params):
        client = client or self.client
        return client.get(self.v3_url(path), params)

    def _rows(self, response) -> list[list[str]]:
        """Assert a well-formed CSV attachment and return its rows (header first)."""
        self.assertEqual(200, response.status_code)
        self.assertEqual("text/csv; charset=utf-8", response["Content-Type"])
        content = b"".join(response.streaming_content).decode("utf-8")
        return list(csv.reader(io.StringIO(content)))

    @staticmethod
    def _by_id(rows: list[list[str]]) -> dict[str, dict[str, str]]:
        header = rows[0]
        return {r[header.index("id")]: dict(zip(header, r, strict=True)) for r in rows[1:]}

    def _problem(self, response) -> dict:
        self.assertEqual(400, response.status_code, response.content[:500])
        return json.loads(response.content)


class TestApiV3CsvExportHappyPath(_CsvExportTestCase):

    def test_header_and_all_rows_with_flattened_refs(self):
        response = self._get("findings/export.csv")
        rows = self._rows(response)
        # Header = the generic flattening of FindingSlim (refs fanned out, tags one column).
        self.assertEqual(_FINDING_DEFAULT_COLUMNS, rows[0])
        # The ref field keys never appear un-flattened.
        for collapsed in ("test", "engagement", "asset", "organization", "reporter"):
            self.assertNotIn(collapsed, rows[0])
        # Every finding the admin can see is exported (whole filtered set, no pagination).
        total = self.get_json("findings", data={"limit": 250})["count"]
        self.assertGreater(total, 0)
        self.assertEqual(total, len(rows) - 1, "export must contain one row per finding, no page limit")

    def test_ref_columns_and_tags_join(self):
        finding = Finding.objects.first()
        finding.tags = ["alpha", "beta"]
        finding.save()
        rows = self._get("findings/export.csv")
        indexed = self._by_id(self._rows(rows))
        row = indexed[str(finding.id)]
        # Ref flattened to id + name (name = the test's ref label).
        self.assertEqual(str(finding.test_id), row["test_id"])
        self.assertEqual(finding.test.title or str(finding.test.test_type), row["test_name"])
        # Tags joined with ';' (tagulous force-lowercases; order preserved).
        self.assertEqual("alpha;beta", row["tags"])

    def test_datetime_columns_are_iso_z(self):
        finding = Finding.objects.first()
        finding.save()  # populate created/updated
        row = self._by_id(self._rows(self._get("findings/export.csv")))[str(finding.id)]
        if row["created"]:
            self.assertTrue(row["created"].endswith("Z"), row["created"])

    def test_response_headers(self):
        response = self._get("findings/export.csv")
        self.assertEqual(200, response.status_code)
        self.assertEqual("text/csv; charset=utf-8", response["Content-Type"])
        self.assertEqual('attachment; filename="findings-export.csv"', response["Content-Disposition"])
        self.assertEqual("alpha", response["X-API-Status"])

    def test_export_csv_does_not_collide_with_int_detail_route(self):
        # "export.csv" cannot match the {int:finding_id} detail route: the export returns CSV and the
        # numeric detail route still returns JSON.
        self.assertEqual("text/csv; charset=utf-8", self._get("findings/export.csv")["Content-Type"])
        detail = self._get(f"findings/{Finding.objects.first().id}")
        self.assertEqual(200, detail.status_code)
        self.assertEqual("application/json", detail["Content-Type"])


class TestApiV3CsvExportFilterContract(_CsvExportTestCase):

    def test_filters_apply(self):
        rows = self._by_id(self._rows(self._get("findings/export.csv", severity="Critical")))
        for row in rows.values():
            self.assertEqual("Critical", row["severity"])
        # Contrast: the unfiltered export has at least as many rows.
        all_rows = self._by_id(self._rows(self._get("findings/export.csv")))
        self.assertGreaterEqual(len(all_rows), len(rows))

    def test_ordering_applies(self):
        rows = self._rows(self._get("findings/export.csv", o="-id"))
        ids = [int(r[0]) for r in rows[1:]]
        self.assertEqual(sorted(ids, reverse=True), ids, "o=-id must sort rows by descending id")

    def test_free_text_q_applies(self):
        finding = Finding.objects.first()
        finding.title = "csv-export-needle-xyz"
        finding.save()
        with_q = self._by_id(self._rows(self._get("findings/export.csv", q="needle-xyz")))
        without_q = self._by_id(self._rows(self._get("findings/export.csv")))
        self.assertIn(str(finding.id), with_q, "the matching finding must be exported")
        self.assertLess(len(with_q), len(without_q), "q= must narrow the exported set")

    def test_fields_narrowing(self):
        rows = self._rows(self._get("findings/export.csv", fields="id,title"))
        self.assertEqual(["id", "title"], rows[0])

    def test_fields_detail_opt_up_adds_impact_column(self):
        finding = Finding.objects.first()
        finding.impact = "csv-impact-value"
        finding.save()
        rows = self._get("findings/export.csv", fields="id,title,impact")
        parsed = self._rows(rows)
        self.assertIn("impact", parsed[0], "?fields= must opt up into the detail column set")
        self.assertEqual("csv-impact-value", self._by_id(parsed)[str(finding.id)]["impact"])

    def test_impact_absent_from_default_export(self):
        # The default export is the slim projection; a detail-only column is not present unless asked.
        self.assertNotIn("impact", self._rows(self._get("findings/export.csv"))[0])

    def test_unknown_field_is_400(self):
        problem = self._problem(self._get("findings/export.csv", fields="id,not_a_field"))
        self.assertTrue(problem["type"].endswith("/fields"))


class TestApiV3CsvExportReservedParams(_CsvExportTestCase):

    """expand/include/limit/offset/pagination/cursor are not applicable to an export -> 400."""

    def test_expand_is_400(self):
        self.assertTrue(self._problem(self._get("findings/export.csv", expand="test"))["type"].endswith("/export"))

    def test_include_is_400(self):
        self.assertTrue(self._problem(self._get("findings/export.csv", include="counts"))["type"].endswith("/export"))

    def test_limit_is_400(self):
        self.assertTrue(self._problem(self._get("findings/export.csv", limit="5"))["type"].endswith("/export"))

    def test_offset_is_400(self):
        self.assertTrue(self._problem(self._get("findings/export.csv", offset="0"))["type"].endswith("/export"))

    def test_pagination_mode_is_400(self):
        self.assertTrue(self._problem(self._get("findings/export.csv", pagination="cursor"))["type"].endswith("/export"))

    def test_cursor_is_400(self):
        self.assertTrue(self._problem(self._get("findings/export.csv", cursor="abc"))["type"].endswith("/export"))


class TestApiV3CsvExportCap(_CsvExportTestCase):

    @override_settings(API_V3_EXPORT_MAX_ROWS=2)
    def test_over_cap_is_400_not_truncation(self):
        # There are more than 2 findings in the fixture, so a cap of 2 rejects the export.
        self.assertGreater(self.get_json("findings", data={"limit": 250})["count"], 2)
        problem = self._problem(self._get("findings/export.csv"))
        self.assertEqual(400, problem["status"])
        self.assertTrue(problem["type"].endswith("/export"))
        self.assertIn("cap", problem["detail"].lower())

    @override_settings(API_V3_EXPORT_MAX_ROWS=100000)
    def test_under_cap_streams(self):
        self.assertEqual(200, self._get("findings/export.csv").status_code)


class TestApiV3CsvExportInjectionHardening(_CsvExportTestCase):

    def test_harden_prefixes_every_formula_trigger(self):
        for trigger in ("=", "+", "-", "@", "\t"):
            self.assertEqual(f"'{trigger}cmd", _harden(f"{trigger}cmd"), f"cell starting with {trigger!r} must be quoted")
        # Safe values are untouched; empty stays empty.
        self.assertEqual("Critical", _harden("Critical"))
        self.assertEqual("", _harden(""))

    def test_dangerous_title_is_quote_prefixed_in_export(self):
        test = Test.objects.first()
        finding = Finding.objects.create(
            title="=SUM(1+1)", severity="High", numerical_severity="S1", description="x",
            test=test, reporter=self.admin, active=True, verified=False,
            date=timezone.now().date(),
        )
        row = self._by_id(self._rows(self._get("findings/export.csv")))[str(finding.id)]
        # The model lowercases the title; the load-bearing assertion is the injection-defense prefix.
        self.assertTrue(row["title"].startswith("'="), f"a formula-like title must be quote-prefixed: {row['title']!r}")
        self.assertIn("sum(1+1)", row["title"].lower())


class TestApiV3CsvExportRbac(_CsvExportTestCase):

    def test_zero_permission_user_export_is_header_only(self):
        zero = Dojo_User.objects.create_user(username="v3_csv_zero", password="x")  # noqa: S106
        rows = self._rows(self._get("findings/export.csv", client=self.token_client(user=zero)))
        self.assertEqual(_FINDING_DEFAULT_COLUMNS, rows[0], "a header row is always emitted")
        self.assertEqual(1, len(rows), "zero-permission user exports no rows (RBAC-scoped empty)")

    def test_unauthorized_rows_absent_from_member_export(self):
        # A member authorized on product A only must never see product B's findings in the export.
        member = Dojo_User.objects.create_user(username="v3_csv_member", password="x")  # noqa: S106
        prod_type = Product_Type.objects.create(name="csv-rbac-pt")
        tt = Test_Type.objects.create(name="csv-rbac-tt")
        product_a = Product.objects.create(name="csv-A", description="x", prod_type=prod_type, sla_configuration_id=1)
        product_b = Product.objects.create(name="csv-B", description="x", prod_type=prod_type, sla_configuration_id=1)
        product_a.authorized_users.add(member)
        ids_a, ids_b = [], []
        for product, bucket in ((product_a, ids_a), (product_b, ids_b)):
            eng = Engagement.objects.create(
                product=product, name=f"{product.name}-eng",
                target_start=timezone.now().date(), target_end=timezone.now().date(),
            )
            test = Test.objects.create(
                engagement=eng, test_type=tt,
                target_start=timezone.now(), target_end=timezone.now(),
            )
            for i in range(2):
                bucket.append(Finding.objects.create(
                    title=f"{product.name}-f{i}", severity="High", numerical_severity="S1",
                    description="x", test=test, reporter=self.admin, active=True, verified=False,
                    date=timezone.now().date(),
                ).id)
        exported = set(self._by_id(self._rows(self._get("findings/export.csv", client=self.token_client(user=member)))))
        for fid in ids_a:
            self.assertIn(str(fid), exported, "product A finding must be in the member's export")
        for fid in ids_b:
            self.assertNotIn(str(fid), exported, "product B finding must NOT leak into the member's export")


class TestApiV3CsvExportQueryCount(_CsvExportTestCase):

    """The export query count is independent of the number of rows streamed (§4.15)."""

    def _bulk_create_findings(self, count: int, test: Test) -> None:
        today = timezone.now().date()
        Finding.objects.bulk_create([
            Finding(
                title=f"csv-qcount {i}", severity="High", numerical_severity="S1",
                description="x", test=test, reporter=self.admin, active=True, verified=False, date=today,
            )
            for i in range(count)
        ])

    def _export_query_count(self) -> int:
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(self.v3_url("findings/export.csv"))
            self.assertEqual(200, response.status_code)
            b"".join(response.streaming_content)  # consume so the chunked iterator + prefetch run in-context
        return len(ctx.captured_queries)

    def test_query_count_is_independent_of_row_count(self):
        test = Test.objects.first()
        self._bulk_create_findings(10, test)
        queries_10 = self._export_query_count()
        self._bulk_create_findings(90, test)
        queries_100 = self._export_query_count()
        self.assertGreaterEqual(self.get_json("findings", data={"limit": 250})["count"], 100)
        self.assertEqual(
            queries_10, queries_100,
            f"CSV export query count must not grow with row count: {queries_10} vs {queries_100}",
        )


class TestApiV3CsvExportAssets(_CsvExportTestCase):

    """A non-finding resource for uniformity: the same generic kernel handles assets (§4.15)."""

    def test_assets_export_flattens_organization_ref(self):
        rows = self._rows(self._get("assets/export.csv"))
        header = rows[0]
        self.assertIn("organization_id", header)
        self.assertIn("organization_name", header)
        self.assertNotIn("organization", header)
        self.assertIn("tags", header)
        total = self.get_json("assets", data={"limit": 250})["count"]
        self.assertEqual(total, len(rows) - 1)

    def test_assets_export_headers(self):
        response = self._get("assets/export.csv")
        self.assertEqual('attachment; filename="assets-export.csv"', response["Content-Disposition"])
        self.assertEqual("alpha", response["X-API-Status"])
