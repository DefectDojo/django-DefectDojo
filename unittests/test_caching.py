from crum import get_current_user, impersonate
from django.test import TestCase, override_settings

from dojo.caching import (
    _L1_STORE,  # noqa: PLC2701 test needs the in-process store
    READ_ONLY_CACHE_MARKER,
    ReadOnlyCachedInstanceError,
    cache_dict_to_model,
    dojo_settings_cache,
    invalidate_dojo_settings_cache,
    model_to_cache_dict,
)
from dojo.models import Dojo_User, System_Settings
from dojo.request_cache import begin_task_cache, cache_for_request_or_task, end_task_cache

from .dojo_test_case import DojoTestCase


@override_settings(SETTINGS_CACHE_L1_TTL=30)
class DojoSettingsCacheTest(TestCase):

    """
    Unit tests for the in-process (L1) read-through decorator (dojo/caching.py).

    There is no shared/L2 tier: the decorator only memoizes in-process and relies
    on L1 reset at request/task boundaries for cross-process freshness.
    """

    def setUp(self):
        _L1_STORE.clear()

    def tearDown(self):
        _L1_STORE.clear()

    def _build_getter(self, *, key="k", returns=1):
        calls = {"n": 0}

        @dojo_settings_cache(key=key)
        def getter():
            calls["n"] += 1
            return returns

        return getter, calls

    def test_l1_memoizes_in_process(self):
        getter, calls = self._build_getter()
        getter()
        getter()
        getter()
        self.assertEqual(calls["n"], 1)        # computed once, then served from L1

    @override_settings(SETTINGS_CACHE_L1_TTL=-1)
    def test_l1_disabled_is_passthrough(self):
        getter, calls = self._build_getter()
        getter()
        getter()
        self.assertEqual(calls["n"], 2)        # recomputed every call when L1 off

    def test_reset_recomputes(self):
        getter, calls = self._build_getter()
        getter()
        _L1_STORE.reset()
        getter()
        self.assertEqual(calls["n"], 2)        # reset drops L1, so it recomputes

    def test_none_result_is_not_cached(self):
        getter, calls = self._build_getter(returns=None)
        self.assertIsNone(getter())
        self.assertIsNone(getter())
        self.assertEqual(calls["n"], 2)        # None recomputed each call (never stored)

    def test_invalidate_recomputes(self):
        getter, calls = self._build_getter(returns=7)
        self.assertEqual(getter(), 7)
        invalidate_dojo_settings_cache("k")
        getter()
        self.assertEqual(calls["n"], 2)        # recomputed after invalidation


class ModelDictRoundTripTest(DojoTestCase):

    def test_round_trip_preserves_field_values(self):
        settings_obj = System_Settings.objects.get(no_cache=True)
        data = model_to_cache_dict(settings_obj)
        self.assertIsInstance(data, dict)
        self.assertEqual(data["id"], settings_obj.pk)
        rebuilt = cache_dict_to_model(System_Settings, data)
        self.assertEqual(rebuilt.pk, settings_obj.pk)
        self.assertEqual(rebuilt.enable_deduplication, settings_obj.enable_deduplication)

    def test_read_only_flag_only_when_requested(self):
        data = model_to_cache_dict(System_Settings.objects.get(no_cache=True))
        # default: saveable (no marker)
        self.assertFalse(getattr(cache_dict_to_model(System_Settings, data), READ_ONLY_CACHE_MARKER, False))
        # read_only=True: tagged as a read-only snapshot
        self.assertTrue(getattr(cache_dict_to_model(System_Settings, data, read_only=True), READ_ONLY_CACHE_MARKER, False))


class SystemSettingsSaveGuardTest(DojoTestCase):

    """
    The read-through cache hands back a read-only snapshot: saving the instance
    returned by ``System_Settings.objects.get()`` must fail loudly, while a fresh
    ``no_cache=True`` instance saves normally.
    """

    def setUp(self):
        _L1_STORE.clear()

    def tearDown(self):
        _L1_STORE.clear()

    def test_saving_cached_instance_raises(self):
        cached = System_Settings.objects.get()  # read-through (cached) path
        self.assertTrue(getattr(cached, READ_ONLY_CACHE_MARKER, False))
        cached.enable_deduplication = not cached.enable_deduplication
        with self.assertRaises(ReadOnlyCachedInstanceError):
            cached.save()

    def test_no_cache_instance_is_saveable(self):
        fresh = System_Settings.objects.get(no_cache=True)
        self.assertFalse(getattr(fresh, READ_ONLY_CACHE_MARKER, False))
        fresh.enable_deduplication = not fresh.enable_deduplication
        fresh.save()  # must not raise


class CacheForRequestOrTaskTest(DojoTestCase):

    """
    ``cache_for_request_or_task`` caches within a task (no request) and isolates by
    the effective (impersonated) user, so per-user results cannot leak between users
    on a reused worker thread.
    """

    def setUp(self):
        self.calls = {"n": 0}

        @cache_for_request_or_task
        def getter():
            self.calls["n"] += 1
            user = get_current_user()
            return (self.calls["n"], user.pk if user else None)

        self.getter = getter
        self.user_a = Dojo_User.objects.create(username="roq_user_a")
        self.user_b = Dojo_User.objects.create(username="roq_user_b")

    def tearDown(self):
        end_task_cache()  # ensure no task cache leaks to the next test

    def test_no_context_is_passthrough(self):
        self.getter()
        self.getter()
        self.assertEqual(self.calls["n"], 2)  # no request and no task -> recomputed

    def test_task_scope_caches(self):
        begin_task_cache()
        with impersonate(self.user_a):
            r1 = self.getter()
            r2 = self.getter()
        self.assertEqual(r1, r2)
        self.assertEqual(self.calls["n"], 1)  # served from the task cache

    def test_task_scope_isolates_users(self):
        begin_task_cache()
        with impersonate(self.user_a):
            a = self.getter()
        with impersonate(self.user_b):
            b = self.getter()  # same task, different user -> must NOT get a's value
        self.assertEqual(a[1], self.user_a.pk)
        self.assertEqual(b[1], self.user_b.pk)
        self.assertNotEqual(a, b)

    def test_end_task_cache_clears(self):
        begin_task_cache()
        with impersonate(self.user_a):
            self.getter()
        end_task_cache()
        with impersonate(self.user_a):
            self.getter()  # no task cache and no request -> recomputed
        self.assertEqual(self.calls["n"], 2)
