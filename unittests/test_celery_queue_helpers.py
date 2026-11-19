"""
The Celery queue helpers in dojo.utils reach the broker the way Celery does.

They used to build their own client from CELERY_BROKER_URL, which leaves out everything Celery is
configured with besides the URL: the broker transport, its TLS options and its credentials. A broker
that signs in with something other than a password in the URL could then be read by Celery but not by
these helpers. These pin that every helper goes through the Celery app's broker connection, by giving
the app a connection to a Redis database of its own and checking the helpers see what is in it.
"""

import json
import os
from unittest.mock import patch

from kombu import Connection

from dojo.utils import get_celery_queue_details, get_celery_queue_length, purge_celery_queue_by_task_name

from .dojo_test_case import DojoTestCase


def _isolated_broker_url():
    # A database nothing else uses, so the test never reads or purges a real queue.
    url = os.environ.get("DD_CELERY_BROKER_URL") or "redis://redis:6379/0"
    return url.rsplit("/", 1)[0] + "/13"


def _message(task):
    return json.dumps({"headers": {"task": task, "eta": None, "expires": None}, "body": ""})


class TestCeleryQueueHelpersUseTheAppConnection(DojoTestCase):

    def setUp(self):
        if not _isolated_broker_url().startswith("redis"):
            self.skipTest("needs a Redis broker")
        self.url = _isolated_broker_url()
        with Connection(self.url) as conn:
            self.client = conn.default_channel.client
            try:
                self.client.ping()
            except Exception:
                self.skipTest("no Redis to test against")
            self.client.delete("celery")
            self.client.rpush("celery", _message("a.task"), _message("b.task"), _message("a.task"))
        self.patcher = patch("dojo.celery.app.connection_for_read", side_effect=lambda: Connection(self.url))
        self.connection_for_read = self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        with Connection(self.url) as conn:
            conn.default_channel.client.delete("celery")

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
        with Connection(self.url) as conn:
            remaining = conn.default_channel.client.lrange("celery", 0, -1)
        self.assertEqual([_message("b.task").encode()], remaining)

    def test_an_unreachable_broker_reads_as_unknown(self):
        self.connection_for_read.side_effect = lambda: Connection("redis://127.0.0.1:1/0", connect_timeout=1)
        self.assertIsNone(get_celery_queue_details())
        self.assertIsNone(purge_celery_queue_by_task_name("a.task"))
