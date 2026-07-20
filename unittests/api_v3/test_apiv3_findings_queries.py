"""
Query-count regression test for API v3 findings (§4.6, §6 OS1) -- the headline guarantee.

The number of SQL queries for a findings list must be **independent of the number of rows
returned**, both with and without ``?expand=``. This is what v3's slim+ref+expand model buys over
v2's post-serialization ``?prefetch=`` (which issues per-row-per-field queries).
"""
from __future__ import annotations

from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from dojo.models import Finding, Test

from .base import ApiV3TestCase


class TestApiV3FindingsQueryCount(ApiV3TestCase):

    def _bulk_create_findings(self, count: int, test: Test) -> None:
        today = timezone.now().date()
        Finding.objects.bulk_create([
            Finding(
                title=f"qcount finding {i}",
                severity="High",
                numerical_severity="S1",
                description="query-count fixture finding",
                test=test,
                reporter=self.admin,
                active=True,
                verified=False,
                date=today,
            )
            for i in range(count)
        ])

    def _query_count(self, params: dict) -> int:
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(self.v3_url("findings"), params)
            self.assertEqual(200, response.status_code, response.content[:500])
        return len(ctx.captured_queries)

    def test_query_count_is_independent_of_row_count(self):
        test = Test.objects.first()

        self._bulk_create_findings(10, test)
        queries_10 = self._query_count({"limit": 250})
        queries_10_expand = self._query_count({"limit": 250, "expand": "test.engagement"})

        self._bulk_create_findings(90, test)  # now 100+ of our findings plus the fixture rows
        queries_100 = self._query_count({"limit": 250})
        queries_100_expand = self._query_count({"limit": 250, "expand": "test.engagement"})

        # Confirm we actually returned ~100+ rows so the assertion is meaningful.
        self.assertGreaterEqual(self.get_json("findings", data={"limit": 250})["count"], 100)

        self.assertEqual(
            queries_10, queries_100,
            f"query count must not grow with row count (no expand): {queries_10} vs {queries_100}",
        )
        self.assertEqual(
            queries_10_expand, queries_100_expand,
            f"query count must not grow with row count (expand): {queries_10_expand} vs {queries_100_expand}",
        )

    def test_query_count_constant_with_beyond_slim_fields(self):
        """
        `?fields=` opting up into detail fields stays row-count-independent (§4.7 Part A/B).

        Includes ``mitigated_by`` (a detail-only relation ref) to prove its extra ``select_related``
        is a fixed join, not a per-row query.
        """
        test = Test.objects.first()
        params = {"limit": 250, "fields": "id,title,impact,references,mitigated_by"}

        self._bulk_create_findings(10, test)
        queries_10 = self._query_count(params)

        self._bulk_create_findings(90, test)
        queries_100 = self._query_count(params)

        self.assertGreaterEqual(self.get_json("findings", data={"limit": 250})["count"], 100)
        self.assertEqual(
            queries_10, queries_100,
            f"opt-up query count must not grow with row count: {queries_10} vs {queries_100}",
        )

    def test_default_list_query_count_unchanged_by_defer(self):
        """
        Deferring the heavy detail columns changes the SELECT column list, never the query count.

        The default list is still the same constant number of queries with defer active (Part B).
        """
        test = Test.objects.first()
        self._bulk_create_findings(50, test)
        default_queries = self._query_count({"limit": 250})
        # Requesting a detail column un-defers it but issues no additional query (row-column, not per-row).
        opt_up_queries = self._query_count({"limit": 250, "fields": "id,title,impact"})
        self.assertEqual(
            default_queries, opt_up_queries,
            f"opting up into a detail column must not add queries: {default_queries} vs {opt_up_queries}",
        )
