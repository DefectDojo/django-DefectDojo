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
