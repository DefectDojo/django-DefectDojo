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

from kombu.transport import redis as kombu_redis

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

    def lpush(self, key, value):
        self.lists.setdefault(key, []).insert(0, value)

    def rpop(self, key):
        items = self.lists.get(key)
        return items.pop() if items else None

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

    def test_queue_details_position_one_is_the_message_a_worker_takes_next(self):
        # kombu's Redis transport adds each message at the head of the list (LPUSH) and workers
        # take them from the tail (BRPOP), so position 1, the oldest, is the last element.
        # Publish and consume with kombu's own Redis channel code over the in-memory list, so the
        # order is pinned against the ends kombu really uses.
        channel = kombu_redis.Channel.__new__(kombu_redis.Channel)
        channel._expires = {}  # set in __init__, which would connect to a server
        channel.conn_or_acquire = contextmanager(lambda: (yield _FakeRedis(self.lists)))
        self.lists["celery"] = []
        for task, eta in [("a.task", "2026-01-01T00:00:00"), ("b.task", None), ("a.task", "2026-01-03T00:00:00")]:
            channel._put("celery", {"body": "", "headers": {"task": task, "eta": eta}, "properties": {}})

        details = get_celery_queue_details()
        self.assertEqual(
            [
                ("a.task", 2, 1, "2026-01-01T00:00:00", 3, "2026-01-03T00:00:00"),
                ("b.task", 1, 2, None, 2, None),
            ],
            [
                (d["task_name"], d["count"], d["oldest_position"], d["oldest_eta"], d["newest_position"], d["newest_eta"])
                for d in details
            ],
        )
        taken = channel._get("celery")["headers"]
        self.assertEqual((details[0]["task_name"], details[0]["oldest_eta"]), (taken["task"], taken["eta"]))

    def test_purge_by_task_name(self):
        self.assertEqual(2, purge_celery_queue_by_task_name("a.task"))
        self.connection_for_read.assert_called_once()
        self.assertEqual([_message("b.task")], self.lists["celery"])

    def test_an_unreachable_broker_reads_as_unknown(self):
        self.connection_for_read.side_effect = ConnectionError("broker unreachable")
        self.assertIsNone(get_celery_queue_length())
        self.assertIsNone(get_celery_queue_details())
        self.assertIsNone(purge_celery_queue_by_task_name("a.task"))
