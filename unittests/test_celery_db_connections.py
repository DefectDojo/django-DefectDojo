import logging
from unittest.mock import Mock, patch

from dojo.celery import (
    close_old_db_connections_after_task,
    close_old_db_connections_before_task,
)

from .dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)


class TestCloseOldDbConnectionsBeforeTask(DojoTestCase):
    """Tests for the task_prerun signal handler that closes stale DB connections."""

    @patch("django.db.close_old_connections")
    def test_eager_task_skips_close(self, mock_close):
        """Eager tasks (used in unit tests) should not close DB connections."""
        task = Mock()
        task.request.is_eager = True
        close_old_db_connections_before_task(task=task)
        mock_close.assert_not_called()

    @patch("django.db.close_old_connections")
    def test_non_eager_task_closes_connections(self, mock_close):
        """Non-eager (normal async) tasks should close stale DB connections."""
        task = Mock()
        task.request.is_eager = False
        close_old_db_connections_before_task(task=task)
        mock_close.assert_called_once()

    @patch("django.db.close_old_connections")
    def test_none_task_closes_connections(self, mock_close):
        """If task is None, connections should still be closed."""
        close_old_db_connections_before_task(task=None)
        mock_close.assert_called_once()


class TestCloseOldDbConnectionsAfterTask(DojoTestCase):
    """Tests for the task_postrun signal handler that closes stale DB connections."""

    @patch("django.db.close_old_connections")
    def test_eager_task_skips_close(self, mock_close):
        """Eager tasks (used in unit tests) should not close DB connections."""
        task = Mock()
        task.request.is_eager = True
        close_old_db_connections_after_task(task=task)
        mock_close.assert_not_called()

    @patch("django.db.close_old_connections")
    def test_non_eager_task_closes_connections(self, mock_close):
        """Non-eager (normal async) tasks should close stale DB connections."""
        task = Mock()
        task.request.is_eager = False
        close_old_db_connections_after_task(task=task)
        mock_close.assert_called_once()

    @patch("django.db.close_old_connections")
    def test_none_task_closes_connections(self, mock_close):
        """If task is None, connections should still be closed."""
        close_old_db_connections_after_task(task=None)
        mock_close.assert_called_once()
