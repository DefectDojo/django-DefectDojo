"""
A plugin can set excess duplicates aside instead of deleting them.

``register_excess_duplicate_handler`` installs one handler for the chunks the excess-duplicate
task removes. When the handler returns True it has dealt with the chunk and nothing is deleted;
with no handler, or one that returns False, the chunk is deleted as before. Only the hand-off is
tested here, so ``bulk_delete_findings`` is mocked and no database is touched.
"""
from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from dojo import tasks


class ExcessDuplicateHandlerTest(SimpleTestCase):
    def setUp(self):
        self.addCleanup(tasks.register_excess_duplicate_handler, None)
        self.chunk = Mock(name="chunk")

    @patch("dojo.tasks.bulk_delete_findings")
    def test_without_a_handler_the_chunk_is_deleted(self, delete):
        tasks.register_excess_duplicate_handler(None)

        tasks._remove_excess_duplicates(self.chunk)

        delete.assert_called_once_with(self.chunk, order_desc=True)

    @patch("dojo.tasks.bulk_delete_findings")
    def test_a_handler_that_takes_the_chunk_stops_the_delete(self, delete):
        handler = Mock(return_value=True)
        tasks.register_excess_duplicate_handler(handler)

        tasks._remove_excess_duplicates(self.chunk)

        handler.assert_called_once_with(self.chunk)
        delete.assert_not_called()

    @patch("dojo.tasks.bulk_delete_findings")
    def test_a_handler_that_declines_leaves_the_delete_in_place(self, delete):
        handler = Mock(return_value=False)
        tasks.register_excess_duplicate_handler(handler)

        tasks._remove_excess_duplicates(self.chunk)

        handler.assert_called_once_with(self.chunk)
        delete.assert_called_once_with(self.chunk, order_desc=True)
