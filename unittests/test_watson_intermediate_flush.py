"""
Unit tests for the AsyncSearchContextMiddleware intermediate-flush hook.

The hook wraps `watson.search.search_context_manager.add_to_context` so that
once the per-request context reaches `WATSON_ASYNC_INDEX_UPDATE_BATCH_SIZE`,
accumulated pks are drained to async celery tasks mid-request and discarded
from the in-memory set.
"""

from unittest.mock import patch

from django.test import override_settings
from watson.search import SearchContextManager, search_context_manager

from dojo.middleware import (
    _drain_search_context_to_async,  # noqa: PLC2701 -- internal helper under test
    install_intermediate_flush_hook,
)
from dojo.models import Product, Product_Type

from .dojo_test_case import DojoTestCase


class TestIntermediateFlushHook(DojoTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Hook is installed at app startup via dojo.apps.ready(); ensure it's
        # present in case test order isolates it.
        install_intermediate_flush_hook()

    def setUp(self):
        super().setUp()
        self.prod_type = Product_Type.objects.create(name="Intermediate Flush PT")
        # Pre-create some products to add to the watson context manually.
        self.products = [
            Product.objects.create(
                name=f"intermediate-flush-prod-{i}",
                description="intermediate flush fixture",
                prod_type=self.prod_type,
            )
            for i in range(5)
        ]

    def _open_context(self):
        if not search_context_manager.is_active():
            search_context_manager.start()

    def _close_context(self):
        # Invalidate before end() so watson doesn't try to bulk-save against
        # the test DB (we only care about the in-memory set bookkeeping).
        if search_context_manager.is_active():
            search_context_manager.invalidate()
            search_context_manager.end()

    def tearDown(self):
        self._close_context()
        super().tearDown()

    def test_drain_dispatches_and_discards(self):
        """_drain_search_context_to_async dispatches per model and clears the set in place."""
        self._open_context()
        objects = search_context_manager._stack[-1][0]
        for p in self.products:
            objects.add((object(), p))
        self.assertEqual(len(objects), len(self.products))

        # `dojo_dispatch_task` is re-imported at call time inside the helper,
        # so patch at its definition site.
        with patch("dojo.celery_dispatch.dojo_dispatch_task") as dispatch:
            _drain_search_context_to_async(objects, source="test")

        self.assertEqual(dispatch.call_count, 1, "one batch dispatched (5 pks << batch size)")
        _task, model_name, pk_list = dispatch.call_args.args
        self.assertEqual(model_name, "dojo.product")
        self.assertEqual(sorted(pk_list), sorted(p.pk for p in self.products))
        self.assertTrue(dispatch.call_args.kwargs.get("force_async"))
        self.assertEqual(len(objects), 0, "drained entries must be discarded from the set")

    @override_settings(WATSON_ASYNC_INDEX_UPDATE_BATCH_SIZE=3)
    def test_add_to_context_triggers_drain_at_threshold(self):
        """Wrapped add_to_context fires the drain exactly when len(objects) >= threshold."""
        self._open_context()
        objects = search_context_manager._stack[-1][0]
        engine_marker = object()

        with patch("dojo.middleware._drain_search_context_to_async") as drain:
            for p in self.products[:2]:
                search_context_manager.add_to_context(engine_marker, p)
            drain.assert_not_called()

            search_context_manager.add_to_context(engine_marker, self.products[2])
            # Third add brings set size to 3 (== threshold) → drain triggers.
            drain.assert_called_once()
            self.assertIs(drain.call_args.args[0], objects)

    @override_settings(WATSON_ASYNC_INDEX_UPDATE_BATCH_SIZE=0)
    def test_threshold_zero_disables_drain(self):
        """Threshold <= 0 short-circuits the hook regardless of set size."""
        self._open_context()
        engine_marker = object()

        with patch("dojo.middleware._drain_search_context_to_async") as drain:
            for p in self.products:
                search_context_manager.add_to_context(engine_marker, p)
            drain.assert_not_called()

    @override_settings(WATSON_ASYNC_INDEX_UPDATE_BATCH_SIZE=2)
    def test_invalidated_context_skips_drain(self):
        """If the search context is invalidated, add_to_context must not drain."""
        self._open_context()
        search_context_manager.invalidate()
        engine_marker = object()

        with patch("dojo.middleware._drain_search_context_to_async") as drain:
            for p in self.products[:3]:
                # add_to_context still records into the (now-invalid) set; the
                # hook should detect the invalid flag and bail out.
                search_context_manager.add_to_context(engine_marker, p)
            drain.assert_not_called()

    @override_settings(WATSON_ASYNC_INDEX_UPDATE_BATCH_SIZE=2)
    def test_ad_hoc_context_manager_does_not_drain(self):
        """
        The intermediate flush is a request-path optimization on the global singleton. An
        ad-hoc SearchContextManager -- e.g. the one update_watson_search_index_for_model builds to
        index its own batch -- must NOT drain, or it would dispatch a clone of itself and loop
        forever (queue ~0, worker pegged, nothing indexed).
        """
        adhoc = SearchContextManager()
        adhoc.start()
        try:
            with patch("dojo.middleware._drain_search_context_to_async") as drain:
                for p in self.products[:3]:  # past the threshold of 2
                    adhoc.add_to_context(object(), p)
                drain.assert_not_called()
        finally:
            adhoc.invalidate()
            adhoc.end()
