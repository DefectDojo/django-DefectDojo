"""
Unit tests for dojo.utils_watson_prefetch — the helper that auto-applies
select_related/prefetch_related to the async watson indexer queryset.
"""

from unittest.mock import patch

from django.test import override_settings
from watson.search import default_search_engine

from dojo.models import Endpoint, Finding, Product, Vulnerability_Id
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
