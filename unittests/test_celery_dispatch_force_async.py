"""
Tests for the `force_async` kwarg on dojo_dispatch_task / we_want_async.

`force_async=True` is for callers (e.g. the watson async indexer middleware)
that should always run their celery task in the background even when the
current user has `import_execution_mode="sync"` or the caller passes `force_sync=True`.
"""

from unittest.mock import patch

from dojo.decorators import we_want_async

from .dojo_test_case import DojoTestCase


class TestForceAsync(DojoTestCase):

    def test_force_async_true_overrides_sync(self):
        """force_async=True wins even when force_sync=True is also present."""
        self.assertTrue(we_want_async(force_sync=True, force_async=True))

    def test_force_async_true_overrides_block_execution(self):
        """force_async=True ignores Dojo_User.wants_block_execution()."""
        with patch("dojo.utils.get_current_user") as get_user, \
                patch("dojo.models.Dojo_User.wants_block_execution", return_value=True):
            get_user.return_value = object()  # any truthy non-None user
            self.assertTrue(we_want_async(force_async=True))

    def test_force_async_false_falls_through_to_normal_logic(self):
        """force_async=False is the same as not passing it at all."""
        with patch("dojo.utils.get_current_user") as get_user, \
                patch("dojo.models.Dojo_User.wants_block_execution", return_value=True):
            get_user.return_value = object()
            self.assertFalse(we_want_async(force_async=False))

    def test_sync_still_honoured_without_force_async(self):
        """Existing force_sync=True behavior is unchanged."""
        self.assertFalse(we_want_async(force_sync=True))
