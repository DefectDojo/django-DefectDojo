"""
async_dupe_delete must run as a singleton so overlapping beat cycles cannot self-collide.

The excess-duplicate delete task is scheduled every 60s, but a run on a large instance can
exceed that interval. Two runs deleting overlapping duplicate sets deadlock in Postgres while
cascade-deleting shared child rows (notably dojo_test_import_finding_action). The task guards
against that with a ``cache.add`` marker: a run is skipped while another holds the marker, and
the marker is always released when the run ends, including on error.

These tests exercise only the task wrapper's locking, so ``_async_dupe_delete_impl`` is mocked
and no database is touched (hence SimpleTestCase and a LocMem cache).
"""
from unittest.mock import patch

from django.core.cache import cache
from django.test import SimpleTestCase, override_settings

from dojo.tasks import DUPE_DELETE_LOCK_KEY, async_dupe_delete

# An isolated in-memory cache so the marker cannot leak between tests or from a real cache.
LOCMEM_CACHE = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "async-dupe-delete-singleton-test",
    },
}


@override_settings(CACHES=LOCMEM_CACHE, DUPE_DELETE_LOCK_EXPIRE=60)
class AsyncDupeDeleteSingletonTest(SimpleTestCase):
    def setUp(self):
        cache.delete(DUPE_DELETE_LOCK_KEY)
        self.addCleanup(cache.delete, DUPE_DELETE_LOCK_KEY)

    @patch("dojo.tasks._async_dupe_delete_impl")
    def test_runs_and_releases_the_lock_when_free(self, mock_impl):
        async_dupe_delete()

        mock_impl.assert_called_once()
        # The marker is released so the next scheduled cycle can run.
        self.assertIsNone(cache.get(DUPE_DELETE_LOCK_KEY))

    @patch("dojo.tasks._async_dupe_delete_impl")
    def test_skips_when_a_previous_run_holds_the_lock(self, mock_impl):
        # Simulate a run that is already in progress.
        cache.add(DUPE_DELETE_LOCK_KEY, value=True, timeout=60)

        async_dupe_delete()

        # The overlapping run must not start the deletion again...
        mock_impl.assert_not_called()
        # ...and must not clear the marker the in-flight run still holds.
        self.assertTrue(cache.get(DUPE_DELETE_LOCK_KEY))

    @patch("dojo.tasks._async_dupe_delete_impl", side_effect=RuntimeError("boom"))
    def test_releases_the_lock_even_when_the_run_raises(self, mock_impl):
        with self.assertRaises(RuntimeError):
            async_dupe_delete()

        mock_impl.assert_called_once()
        # A failed run must still free the marker, or deletion would be wedged until the
        # marker's timeout expires.
        self.assertIsNone(cache.get(DUPE_DELETE_LOCK_KEY))
