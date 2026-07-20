"""Findings read-path contract tests for API v3 (§4.3-§4.9, OS1)."""
from __future__ import annotations

from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext

from dojo.location.models import Location, LocationFindingReference
from dojo.models import Finding, User

from .base import ApiV3TestCase

_SLIM_KEYS = {
    "id", "title", "severity", "active", "verified", "false_p", "duplicate", "risk_accepted",
    "out_of_scope", "is_mitigated", "date", "cwe", "test", "engagement", "asset",
    "organization", "reporter", "locations_count", "tags", "created", "updated",
}


class TestApiV3FindingsSlim(ApiV3TestCase):

    def test_list_envelope_shape(self):
        body = self.get_json("findings")
        self.assertEqual({"count", "next", "previous", "results"}, set(body) - {"meta"})
        self.assertIsInstance(body["count"], int)
        self.assertIsInstance(body["results"], list)
        self.assertGreater(body["count"], 0)

    def test_slim_shape_and_denormalized_parent_refs(self):
        row = self.get_json("findings")["results"][0]
        self.assertEqual(_SLIM_KEYS, set(row))
        # Refs are closed {id, name}; parent chain is denormalized onto the finding.
        for key in ("test", "engagement", "asset", "organization"):
            self.assertEqual({"id", "name"}, set(row[key]), key)
        self.assertIsInstance(row["locations_count"], int)
        self.assertIsInstance(row["tags"], list)

    def test_datetime_is_iso_z(self):
        row = self.get_json("findings")["results"][0]
        if row["created"]:
            self.assertTrue(row["created"].endswith("Z"), row["created"])

    def test_detail_adds_heavy_fields(self):
        row = self.get_json("findings")["results"][0]
        detail = self.get_json(f"findings/{row['id']}")
        for key in ("description", "mitigation", "impact", "file_path", "line", "mitigated", "mitigated_by"):
            self.assertIn(key, detail)

    def test_detail_unknown_or_unauthorized_is_404(self):
        self.get_json("findings/99999999", expected=404)


class TestApiV3FindingsExpand(ApiV3TestCase):

    def test_expand_test_engagement_inlines_slim(self):
        row = self.get_json("findings", data={"expand": "test.engagement"})["results"][0]
        # test ref swapped for the test slim shape (has a title-derived name + its own refs).
        self.assertIn("test_type", row["test"])
        self.assertIn("engagement", row["test"])
        # engagement nested inside test is itself a slim (carries name, not just id).
        self.assertIn("name", row["test"]["engagement"])
        self.assertIn("asset", row["test"]["engagement"])

    def test_expand_reporter(self):
        row = self.get_json("findings", data={"expand": "reporter"})["results"][0]
        if row["reporter"] is not None:
            self.assertIn("username", row["reporter"])

    def test_expand_unknown_relation_is_400(self):
        body = self.get_json("findings", data={"expand": "not_a_relation"}, expected=400)
        self.assertEqual(400, body["status"])

    def test_expand_budget_exceeded_is_400(self):
        with override_settings(API_V3_EXPAND_BUDGET=1):
            self.get_json("findings", data={"expand": "test.engagement,reporter"}, expected=400)


class TestApiV3FindingsFields(ApiV3TestCase):

    def test_fields_subsets_output(self):
        row = self.get_json("findings", data={"fields": "id,title"})["results"][0]
        self.assertEqual({"id", "title"}, set(row))

    def test_fields_always_includes_id(self):
        row = self.get_json("findings", data={"fields": "title"})["results"][0]
        self.assertIn("id", row)

    def test_unknown_field_is_400(self):
        self.get_json("findings", data={"fields": "id,not_a_field"}, expected=400)


class TestApiV3FindingsFieldsOptUp(ApiV3TestCase):

    """`?fields=` on the LIST endpoint may opt UP into the detail field set (§4.7 Part A)."""

    def test_fields_opts_up_into_detail_fields(self):
        # impact + references are detail-only fields; requesting them returns exactly the projection.
        row = self.get_json("findings", data={"fields": "id,title,impact,references"})["results"][0]
        self.assertEqual({"id", "title", "impact", "references"}, set(row))

    def test_detail_fields_absent_from_default_list(self):
        # The default (no fields=) list is the slim shape exactly -- detail fields never appear.
        row = self.get_json("findings")["results"][0]
        self.assertEqual(_SLIM_KEYS, set(row))
        self.assertNotIn("impact", row)
        self.assertNotIn("references", row)

    def test_opt_up_value_matches_detail_get(self):
        finding = Finding.objects.first()
        finding.impact = "opt-up-impact-value"
        finding.save(update_fields=["impact"])
        row = next(
            r for r in self.get_json("findings", data={"fields": "id,impact", "limit": 250})["results"]
            if r["id"] == finding.id
        )
        self.assertEqual("opt-up-impact-value", row["impact"])
        # Identical to what the detail GET (which serializes with FindingDetail) returns.
        self.assertEqual(self.get_json(f"findings/{finding.id}")["impact"], row["impact"])

    def test_detail_only_relation_ref_via_fields(self):
        # mitigated_by is a detail-only relation rendered as a {id, name} ref (fixed join, Part A).
        finding = Finding.objects.first()
        finding.mitigated_by = self.admin
        finding.save(update_fields=["mitigated_by"])
        row = next(
            r for r in self.get_json("findings", data={"fields": "id,mitigated_by", "limit": 250})["results"]
            if r["id"] == finding.id
        )
        self.assertEqual({"id", "mitigated_by"}, set(row))
        self.assertEqual({"id", "name"}, set(row["mitigated_by"]))
        self.assertEqual(self.admin.username, row["mitigated_by"]["name"])

    def test_fields_mixing_slim_detail_and_expandable_keys(self):
        # title (slim) + impact (detail) + locations (an EXPANDABLE key, not a model field).
        body = self.get_json(
            "findings", data={"fields": "id,title,impact,locations", "expand": "locations"},
        )
        row = body["results"][0]
        self.assertEqual({"id", "title", "impact", "locations"}, set(row))
        self.assertIsInstance(row["locations"], list)

    def test_unknown_field_still_400_under_opt_up_allowlist(self):
        self.get_json("findings", data={"fields": "id,not_a_field"}, expected=400)


class TestApiV3FindingsDefer(ApiV3TestCase):

    """Part B: the LIST row query defers the heavy detail columns that were not requested."""

    def _main_row_sql(self, params: dict) -> str:
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(self.v3_url("findings"), params)
            self.assertEqual(200, response.status_code, response.content[:500])
        # The main row query is the one selecting the finding table's slim `title` column.
        rows = [q["sql"] for q in ctx.captured_queries if '"dojo_finding"."title"' in q["sql"]]
        self.assertEqual(1, len(rows), f"expected exactly one main finding row query, got {len(rows)}")
        return rows[0]

    def test_default_list_does_not_select_deferred_columns(self):
        sql = self._main_row_sql({"limit": 250})
        self.assertIn('"dojo_finding"."title"', sql)          # a slim column is always selected
        self.assertNotIn('"dojo_finding"."impact"', sql)      # heavy detail columns are deferred
        self.assertNotIn('"dojo_finding"."description"', sql)
        self.assertNotIn('"dojo_finding"."mitigation"', sql)

    def test_requesting_impact_un_defers_impact(self):
        sql = self._main_row_sql({"limit": 250, "fields": "id,impact"})
        self.assertIn('"dojo_finding"."impact"', sql)         # requested -> selected
        # Other heavy detail columns stay deferred ("un-defers exactly impact").
        self.assertNotIn('"dojo_finding"."mitigation"', sql)
        self.assertNotIn('"dojo_finding"."description"', sql)


class TestApiV3FindingsFilters(ApiV3TestCase):

    def test_filter_severity(self):
        body = self.get_json("findings", data={"severity": "High"})
        for row in body["results"]:
            self.assertEqual("High", row["severity"])

    def test_filter_active_boolean(self):
        body = self.get_json("findings", data={"active": "true"})
        for row in body["results"]:
            self.assertTrue(row["active"])

    def test_ordering(self):
        body = self.get_json("findings", data={"o": "-id"})
        ids = [r["id"] for r in body["results"]]
        self.assertEqual(ids, sorted(ids, reverse=True))

    def test_unknown_ordering_is_400(self):
        self.get_json("findings", data={"o": "not_orderable"}, expected=400)

    def test_severity_ordering_is_by_rank_not_alphabetical(self):
        rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        severities = [r["severity"] for r in self.get_json("findings", data={"o": "severity", "limit": 250})["results"]]
        ranks = [rank[s] for s in severities]
        # Rank-sorted ascending -> Critical first (§4.9), never alphabetical.
        self.assertEqual(ranks, sorted(ranks), severities)
        # Alphabetical would place "Info" before "Medium"; rank ordering must not.
        if "Medium" in severities and "Info" in severities:
            self.assertLess(severities.index("Medium"), severities.index("Info"), severities)

    def test_severity_ordering_descending_reverses_rank(self):
        rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        severities = [r["severity"] for r in self.get_json("findings", data={"o": "-severity", "limit": 250})["results"]]
        ranks = [rank[s] for s in severities]
        self.assertEqual(ranks, sorted(ranks, reverse=True), severities)

    def test_q_free_text_search(self):
        body = self.get_json("findings", data={"q": "DUMMY", "limit": 250})
        self.assertGreater(body["count"], 0)
        for row in body["results"]:
            self.assertIn("dummy", row["title"].lower())

    def test_q_no_match_returns_empty(self):
        body = self.get_json("findings", data={"q": "zzz_no_such_finding_zzz"})
        self.assertEqual(0, body["count"])

    def test_unknown_filter_param_is_400(self):
        self.get_json("findings", data={"not_a_real_filter": "x"}, expected=400)


class TestApiV3FindingsInclude(ApiV3TestCase):

    def test_include_counts(self):
        body = self.get_json("findings", data={"include": "counts"})
        counts = body["meta"]["counts"]
        for key in ("total", "active", "verified", "duplicate", "severity"):
            self.assertIn(key, counts)
        self.assertEqual(body["count"], counts["total"])
        self.assertEqual(
            {"Critical", "High", "Medium", "Low", "Info"}, set(counts["severity"]),
        )

    def test_unknown_include_is_400(self):
        self.get_json("findings", data={"include": "bogus"}, expected=400)


class TestApiV3FindingsPagination(ApiV3TestCase):

    def test_limit_and_next(self):
        body = self.get_json("findings", data={"limit": 2})
        self.assertLessEqual(len(body["results"]), 2)
        if body["count"] > 2:
            self.assertIsNotNone(body["next"])
        self.assertIsNone(body["previous"])

    def test_offset_previous(self):
        body = self.get_json("findings", data={"limit": 2, "offset": 2})
        self.assertIsNotNone(body["previous"])

    def test_cursor_mode_smoke(self):
        # Cursor mode is implemented (see test_apiv3_cursor for the full contract): count/previous
        # are null and the envelope shape is otherwise unchanged.
        body = self.get_json("findings", data={"pagination": "cursor", "limit": 2})
        self.assertIsNone(body["count"])
        self.assertIsNone(body["previous"])
        self.assertLessEqual(len(body["results"]), 2)

    def test_bad_limit_400(self):
        self.get_json("findings", data={"limit": "-1"}, expected=400)

    def test_count_exact_below_cap(self):
        body = self.get_json("findings")
        # Default CAP is large; count is exact and no count_exact flag appears.
        self.assertNotIn("count_exact", body.get("meta", {}))

    @override_settings(API_V3_COUNT_CAP=1)
    def test_count_switches_to_estimate_above_cap(self):
        body = self.get_json("findings")
        # Above the (lowered) cap: estimate clamped to >= CAP+1, flagged count_exact false.
        self.assertGreaterEqual(body["count"], 2)
        self.assertIn("count_exact", body["meta"])
        self.assertFalse(body["meta"]["count_exact"])


class TestApiV3FindingsLocationsExpand(ApiV3TestCase):

    def _attach_location(self, finding: Finding, value: str, status: str = "Active") -> None:
        location = Location.objects.create(location_type="url", location_value=value)
        LocationFindingReference.objects.create(location=location, finding=finding, status=status)

    def test_expand_locations_swaps_count_for_edge_rows(self):
        finding = Finding.objects.first()
        existing = finding.locations.count()  # fixture may already attach some
        self._attach_location(finding, "https://example.com/os2-a")
        self._attach_location(finding, "https://example.com/os2-b", status="Mitigated")

        detail = self.get_json(f"findings/{finding.id}", data={"expand": "locations"})
        # `locations_count` is swapped for the edge rows (§4.6).
        self.assertNotIn("locations_count", detail)
        self.assertIn("locations", detail)
        rows = detail["locations"]
        self.assertEqual(existing + 2, len(rows))
        for row in rows:
            # OS4 added `auditor` to the expand=locations edge rows (§12).
            self.assertEqual({"location", "status", "audit_time", "auditor"}, set(row))
            self.assertEqual({"id", "name", "type"}, set(row["location"]))
        by_name = {row["location"]["name"]: row for row in rows}
        self.assertEqual("url", by_name["https://example.com/os2-a"]["location"]["type"])
        self.assertEqual("Active", by_name["https://example.com/os2-a"]["status"])
        self.assertEqual("Mitigated", by_name["https://example.com/os2-b"]["status"])

    def test_slim_without_expand_keeps_locations_count(self):
        row = self.get_json("findings")["results"][0]
        self.assertIn("locations_count", row)
        self.assertNotIn("locations", row)

    def test_expand_into_locations_is_400(self):
        self.get_json("findings", data={"expand": "locations.location"}, expected=400)

    def test_expand_locations_query_count_constant(self):
        test = Finding.objects.first().test
        params = {"limit": 250, "expand": "locations"}

        def query_count() -> int:
            with CaptureQueriesContext(connection) as ctx:
                response = self.client.get(self.v3_url("findings"), params)
                self.assertEqual(200, response.status_code, response.content[:500])
            return len(ctx.captured_queries)

        Finding.objects.bulk_create([
            Finding(title=f"loc qcount {i}", severity="High", numerical_severity="S1",
                    description="x", test=test, reporter=self.admin, active=True, verified=False)
            for i in range(10)
        ])
        first = query_count()
        Finding.objects.bulk_create([
            Finding(title=f"loc qcount b{i}", severity="High", numerical_severity="S1",
                    description="x", test=test, reporter=self.admin, active=True, verified=False)
            for i in range(90)
        ])
        second = query_count()
        self.assertEqual(first, second, f"expand=locations query count grew: {first} -> {second}")


class TestApiV3FindingsRbac(ApiV3TestCase):

    def test_include_counts_and_list_respect_authorized_queryset(self):
        """A user with no product access sees an empty list and zeroed counts (RBAC via querysets)."""
        limited = User.objects.create_user(username="v3_limited", password="x")  # noqa: S106
        client = self.token_client(user=limited)
        body = self.get_json("findings", client=client, data={"include": "counts"})
        self.assertEqual(0, body["count"])
        self.assertEqual([], body["results"])
        self.assertEqual(0, body["meta"]["counts"]["total"])
