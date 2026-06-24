from unittest import mock

from django.test import TestCase, override_settings

from dojo import caching
from dojo.caching import (
    _L1_STORE,  # noqa: PLC2701 test needs the in-process store
    cache_dict_to_model,
    dojo_settings_cache,
    invalidate_dojo_settings_cache,
    model_to_cache_dict,
)
from dojo.models import System_Settings

from .dojo_test_case import DojoTestCase


class _FakeCache:

    """Dict-backed stand-in for ``django.core.cache.cache`` that counts access."""

    def __init__(self):
        self.store = {}
        self.gets = 0
        self.sets = 0
        self.deletes = 0

    def get(self, key, default=None):
        self.gets += 1
        return self.store.get(key, default)

    def set(self, key, value, timeout=None):
        self.sets += 1
        self.store[key] = value

    def delete(self, key):
        self.deletes += 1
        self.store.pop(key, None)


@override_settings(SETTINGS_CACHE_L2_TTL=300, SETTINGS_CACHE_L1_TTL=30)
class DojoSettingsCacheTest(TestCase):

    """Unit tests for the simplified L1+L2 read-through decorator (dojo/caching.py)."""

    def setUp(self):
        self.fake = _FakeCache()
        self._patch = mock.patch.object(caching, "cache", self.fake)
        self._patch.start()
        _L1_STORE.clear()

    def tearDown(self):
        self._patch.stop()
        _L1_STORE.clear()

    def _build_getter(self, *, key="k", returns=1):
        calls = {"n": 0}

        @dojo_settings_cache(key=key)
        def getter():
            calls["n"] += 1
            return returns

        return getter, calls

    @override_settings(SETTINGS_CACHE_L1_TTL=-1)
    def test_l1_disabled_consults_l2_every_call(self):
        getter, calls = self._build_getter()
        self.assertEqual(getter(), 1)
        self.assertEqual(getter(), 1)  # served from L2, fn not re-run
        self.assertEqual(calls["n"], 1)        # computed once
        self.assertEqual(self.fake.gets, 2)    # L2 consulted every call

    def test_l1_serves_without_l2(self):
        getter, calls = self._build_getter()
        getter()
        getter()
        getter()
        self.assertEqual(calls["n"], 1)
        self.assertEqual(self.fake.gets, 1)    # only the first call reaches L2

    @override_settings(SETTINGS_CACHE_L2_TTL=-1)
    def test_l2_ttl_negative_disables_l2(self):
        getter, calls = self._build_getter()
        getter()
        getter()
        self.assertEqual(self.fake.gets, 0)    # L2 never consulted
        self.assertEqual(self.fake.sets, 0)
        self.assertEqual(calls["n"], 1)        # but L1 still memoizes in-process

    @override_settings(SETTINGS_CACHE_L1_TTL=-1, SETTINGS_CACHE_L2_TTL=-1)
    def test_both_tiers_disabled_is_passthrough(self):
        getter, calls = self._build_getter()
        getter()
        getter()
        self.assertEqual(calls["n"], 2)        # recomputed every call
        self.assertEqual(self.fake.gets, 0)    # L2 never consulted

    def test_reset_clears_l1(self):
        getter, calls = self._build_getter()
        getter()
        _L1_STORE.reset()
        getter()
        self.assertEqual(calls["n"], 1)        # reset drops L1, but L2 still serves
        self.assertEqual(self.fake.gets, 2)    # 2nd call re-reads L2 after reset

    def test_none_result_is_not_cached(self):
        getter, calls = self._build_getter(returns=None)
        self.assertIsNone(getter())
        self.assertIsNone(getter())
        self.assertEqual(calls["n"], 2)        # None recomputed each call (never stored)
        self.assertEqual(self.fake.sets, 0)

    def test_invalidate_clears_l1_and_l2(self):
        getter, calls = self._build_getter(returns=7)
        self.assertEqual(getter(), 7)
        invalidate_dojo_settings_cache("k")
        getter()
        self.assertEqual(calls["n"], 2)        # recomputed after invalidation

    @override_settings(SETTINGS_CACHE_L2_TTL=-1)
    def test_invalidate_skips_l2_when_disabled(self):
        # With L2 off the backend may be unreachable (no Redis in unit tests);
        # invalidation must not call cache.delete.
        invalidate_dojo_settings_cache("k")
        self.assertEqual(self.fake.deletes, 0)


class ModelDictRoundTripTest(DojoTestCase):

    def test_round_trip_preserves_field_values(self):
        settings_obj = System_Settings.objects.get(no_cache=True)
        data = model_to_cache_dict(settings_obj)
        self.assertIsInstance(data, dict)
        self.assertEqual(data["id"], settings_obj.pk)
        rebuilt = cache_dict_to_model(System_Settings, data)
        self.assertEqual(rebuilt.pk, settings_obj.pk)
        self.assertEqual(rebuilt.enable_deduplication, settings_obj.enable_deduplication)
