"""
Unit tests for dojo.utils_watson_prefetch — the helper that auto-applies
select_related/prefetch_related to the async watson indexer queryset.
"""

import contextlib
from unittest.mock import patch

from django.contrib.auth.models import User
from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from watson.search import default_search_engine

from dojo.models import (
    Endpoint,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
    Vulnerability_Id,
)
from dojo.utils_watson_prefetch import (
    build_indexing_queryset,
    derive_relation_paths,
)

from .dojo_test_case import DojoTestCase


class TestDeriveRelationPaths(DojoTestCase):

    """Pure-Python introspection of adapter fields/store paths."""

    def _adapter(self, model):
        return default_search_engine.get_adapter(model)

    def test_product_paths(self):
        """Product adapter stores `prod_type__name` — single FK hop, select_related."""
        select, prefetch = derive_relation_paths(Product, self._adapter(Product))
        self.assertIn("prod_type", select)
        self.assertEqual(prefetch, set())

    def test_finding_paths(self):
        """Finding adapter has deep FK chains + jira_issue FK; all are select_related."""
        select, _ = derive_relation_paths(Finding, self._adapter(Finding))
        self.assertIn("test__engagement__product", select)
        self.assertIn("jira_issue", select)

    def test_vulnerability_id_paths(self):
        """Vulnerability_Id stores finding__test__engagement__product__name."""
        select, _ = derive_relation_paths(Vulnerability_Id, self._adapter(Vulnerability_Id))
        self.assertIn("finding__test__engagement__product", select)

    def test_endpoint_paths(self):
        """Endpoint stores product__name — single FK hop."""
        select, _ = derive_relation_paths(Endpoint, self._adapter(Endpoint))
        self.assertIn("product", select)

    def test_unknown_path_dropped_silently(self):
        """Adapter paths that don't resolve against _meta are dropped, not raised."""

        class FakeAdapter:
            fields = ("does_not_exist__nope",)
            store = ()

        select, prefetch = derive_relation_paths(Product, FakeAdapter())
        self.assertEqual(select, set())
        self.assertEqual(prefetch, set())

    def test_plain_field_names_ignored(self):
        """Field paths with no `__` (i.e. local CharField/TextField) are skipped."""

        class FakeAdapter:
            fields = ("name", "description")
            store = ()

        select, prefetch = derive_relation_paths(Product, FakeAdapter())
        self.assertEqual(select, set())
        self.assertEqual(prefetch, set())


class TestBuildIndexingQueryset(DojoTestCase):

    """Behaviour of build_indexing_queryset under settings + error conditions."""

    def test_prefetch_enabled_applies_select_related(self):
        adapter = default_search_engine.get_adapter(Finding)
        qs = build_indexing_queryset(Finding, [], adapter)
        # select_related populates query.select_related as a dict
        self.assertTrue(qs.query.select_related)

    @override_settings(WATSON_INDEX_PREFETCH_ENABLED=False)
    def test_setting_disabled_returns_plain_queryset(self):
        adapter = default_search_engine.get_adapter(Finding)
        qs = build_indexing_queryset(Finding, [], adapter)
        # Plain queryset has select_related == False (the default).
        self.assertFalse(qs.query.select_related)

    def test_falls_back_when_derivation_raises(self):
        """If path derivation blows up we log + return the plain queryset."""
        adapter = default_search_engine.get_adapter(Finding)
        with patch(
            "dojo.utils_watson_prefetch.derive_relation_paths",
            side_effect=RuntimeError("boom"),
        ), self.assertLogs("dojo.utils_watson_prefetch", level="ERROR") as captured:
            qs = build_indexing_queryset(Finding, [], adapter)
        self.assertFalse(qs.query.select_related)
        self.assertTrue(any("falling back" in msg for msg in captured.output))

    def test_unresolved_paths_are_dropped(self):
        """Adapter paths that don't classify produce a plain queryset, not an error."""
        adapter = default_search_engine.get_adapter(Finding)
        with patch(
            "dojo.utils_watson_prefetch.derive_relation_paths",
            return_value=(set(), set()),
        ):
            qs = build_indexing_queryset(Finding, [], adapter)
        self.assertFalse(qs.query.select_related)


class TestPrefetchReducesQueriesOnIndexerPath(DojoTestCase):

    """
    End-to-end query-count check: iterating the indexer queryset and walking the
    adapter's FK chain (`finding.test.engagement.product.name`, `finding.jira_issue`)
    must produce dramatically fewer queries with prefetch enabled than with the
    plain queryset. Locks in the N+1 elimination claim that perf tests only
    observe indirectly through the import path.
    """

    N_FINDINGS = 5

    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        user, _ = User.objects.get_or_create(username="watson_prefetch_user", defaults={"is_active": True})
        pt, _ = Product_Type.objects.get_or_create(name="Watson Prefetch PT")
        product = Product.objects.create(name="watson-prefetch-product", description="x", prod_type=pt)
        eng = Engagement.objects.create(product=product, target_start=now, target_end=now)
        tt, _ = Test_Type.objects.get_or_create(name="Watson Prefetch TT")
        test = Test.objects.create(engagement=eng, test_type=tt, target_start=now, target_end=now)
        cls.pk_list = [
            Finding.objects.create(
                test=test, title=f"watson-prefetch-{i}", severity="Medium", reporter=user,
            ).pk
            for i in range(cls.N_FINDINGS)
        ]

    def _walk_adapter_paths(self, finding):
        # Touch the deep FK chains the Finding adapter resolves at index time.
        # Without prefetch, each attribute hop is its own SELECT per finding.
        # jira_issue is a reverse OneToOne — `_state.fields_cache` membership
        # signals select_related populated it without triggering a fresh fetch.
        _ = finding.test.engagement.product.name
        # Access fires the query (or hits a populated cache); either way the
        # query-count assertion captures the difference.
        with contextlib.suppress(finding.__class__.jira_issue.RelatedObjectDoesNotExist):
            _ = finding.jira_issue

    def _count_queries_with(self, *, prefetch_enabled):
        adapter = default_search_engine.get_adapter(Finding)
        with override_settings(WATSON_INDEX_PREFETCH_ENABLED=prefetch_enabled):
            qs = build_indexing_queryset(Finding, self.pk_list, adapter)
            with CaptureQueriesContext(connection) as ctx:
                for f in qs:
                    self._walk_adapter_paths(f)
        return len(ctx.captured_queries)

    def test_prefetch_enabled_uses_fewer_queries_than_plain_qs(self):
        with_prefetch = self._count_queries_with(prefetch_enabled=True)
        without_prefetch = self._count_queries_with(prefetch_enabled=False)

        # Plain qs: 1 SELECT + N * (test + engagement + product + jira_issue) ≈ 1 + 4N
        # Prefetched qs: 1 SELECT with joins (select_related collapses the FK chain)
        # Concrete numbers for N=5: ~21 vs 1. Assert a healthy margin without
        # pinning exact counts (watson registrations may add more paths later).
        self.assertLess(
            with_prefetch, without_prefetch,
            f"prefetch should reduce queries (with={with_prefetch}, without={without_prefetch})",
        )
        self.assertGreaterEqual(
            without_prefetch - with_prefetch, self.N_FINDINGS,
            f"prefetch should save at least N queries on N findings "
            f"(saved {without_prefetch - with_prefetch}, N={self.N_FINDINGS})",
        )

    def test_prefetch_enabled_single_query_for_fk_chain(self):
        """With prefetch on, the FK chain walk must not issue extra SELECTs."""
        adapter = default_search_engine.get_adapter(Finding)
        qs = build_indexing_queryset(Finding, self.pk_list, adapter)
        # Force evaluation first, then capture only the attribute-walk phase.
        findings = list(qs)
        with CaptureQueriesContext(connection) as ctx:
            for f in findings:
                self._walk_adapter_paths(f)
        self.assertEqual(
            len(ctx.captured_queries), 0,
            f"adapter FK walk should be query-free after prefetch; got {len(ctx.captured_queries)}: "
            f"{[q['sql'] for q in ctx.captured_queries]}",
        )
