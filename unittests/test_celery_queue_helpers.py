"""
The Celery queue helpers in dojo.utils reach the broker the way Celery does.

They used to build their own client from CELERY_BROKER_URL, which leaves out everything Celery is
configured with besides the URL: the broker transport, its TLS options and its credentials. A broker
that signs in with something other than a password in the URL could then be read by Celery but not by
these helpers. These pin that every helper goes through the Celery app's broker connection: the app's
connection is replaced with one whose Redis client holds a queue in memory, so the helpers can only
see that queue by asking the app, and the tests need no Redis server.
"""

import json
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

from dojo.utils import get_celery_queue_details, get_celery_queue_length, purge_celery_queue_by_task_name

from .dojo_test_case import DojoTestCase


def _message(task):
    return json.dumps({"headers": {"task": task, "eta": None, "expires": None}, "body": ""}).encode()


class _Pipeline:
    def __init__(self, client):
        self.client = client
        self.ops = []

    def lrem(self, key, count, value):
        self.ops.append((key, count, value))

    def execute(self):
        for key, count, value in self.ops:
            self.client.lrem(key, count, value)


class _FakeRedis:

    """The few list commands the helpers send, over an in-memory list per key."""

    def __init__(self, lists):
        self.lists = lists

    def lrange(self, key, start, end):
        items = self.lists.get(key, [])
        return items[start:] if end == -1 else items[start:end + 1]

    def lrem(self, key, count, value):
        items = self.lists.get(key, [])
        if value in items:
            items.remove(value)

    def pipeline(self):
        return _Pipeline(self)


class TestCeleryQueueHelpersUseTheAppConnection(DojoTestCase):

    def setUp(self):
        self.lists = {"celery": [_message("a.task"), _message("b.task"), _message("a.task")]}
        client = _FakeRedis(self.lists)

        @contextmanager
        def simple_queue(name):
            queue = MagicMock()
            queue.qsize.return_value = len(self.lists.get(name, []))
            yield queue

        @contextmanager
        def connection():
            conn = MagicMock()
            conn.default_channel.client = client
            conn.SimpleQueue.side_effect = simple_queue
            yield conn

        self.patcher = patch("dojo.celery.app.connection_for_read", side_effect=connection)
        self.connection_for_read = self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def test_queue_length(self):
        self.assertEqual(3, get_celery_queue_length())
        self.connection_for_read.assert_called_once()

    def test_queue_details(self):
        details = get_celery_queue_details()
        self.assertEqual(
            [("a.task", 2, 1, 3), ("b.task", 1, 2, 2)],
            [(d["task_name"], d["count"], d["oldest_position"], d["newest_position"]) for d in details],
        )
        self.connection_for_read.assert_called_once()

    def test_purge_by_task_name(self):
        self.assertEqual(2, purge_celery_queue_by_task_name("a.task"))
        self.connection_for_read.assert_called_once()
        self.assertEqual([_message("b.task")], self.lists["celery"])

    def test_an_unreachable_broker_reads_as_unknown(self):
        self.connection_for_read.side_effect = ConnectionError("broker unreachable")
        self.assertIsNone(get_celery_queue_length())
        self.assertIsNone(get_celery_queue_details())
        self.assertIsNone(purge_celery_queue_by_task_name("a.task"))
