"""
Concurrency tests for the import-time test tag write (``BaseImporter.set_test_tags_safe``).

Tagulous keeps a reference count on every tag row (``dojo_tagulous_test_tags``) and
``Test.tags.set()`` updates those rows one at a time, in the order the tags were supplied.
Two imports writing an overlapping tag set in different orders could therefore each hold a
tag row the other one needs, and Postgres broke the cycle by aborting one of them with
``deadlock detected ... while updating tuple (...) in relation "dojo_tagulous_test_tags"``.

These tests use a second real database connection and real commits, which a ``TestCase``
cannot do (see unittests/test_dedupe_delete_commit_race.py for the same pattern). The
interleaving is forced: the concurrent transaction takes its second row lock only once the
import is blocked on its first one.
"""

import threading
import time
import uuid
from unittest import mock

from django.db import OperationalError, connection, connections, transaction
from django.db.models import F
from django.test import SimpleTestCase
from django.utils import timezone

from dojo.importers import base_importer
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import (
    Alerts,
    Development_Environment,
    Engagement,
    Notifications,
    Product,
    Product_Type,
    Test,
    Test_Type,
    User,
)

WAIT_TIMEOUT_SECONDS = 20


def _backend_pid():
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_backend_pid()")
        return cursor.fetchone()[0]


def _is_waiting_on_a_lock(pid):
    with connection.cursor() as cursor:
        cursor.execute("SELECT cardinality(pg_blocking_pids(%s)) > 0", [pid])
        return cursor.fetchone()[0]


def _wait_for(predicate, what):
    deadline = time.monotonic() + WAIT_TIMEOUT_SECONDS
    while not predicate():
        if time.monotonic() > deadline:
            msg = f"timed out after {WAIT_TIMEOUT_SECONDS}s waiting for {what}"
            raise AssertionError(msg)
        time.sleep(0.01)


def _deadlock_error():
    cause = Exception("deadlock detected")
    cause.sqlstate = "40P01"
    exc = OperationalError("deadlock detected")
    exc.__cause__ = cause
    return exc


def _non_transient_error():
    cause = Exception("canceling statement due to statement timeout")
    cause.sqlstate = "57014"
    exc = OperationalError("canceling statement due to statement timeout")
    exc.__cause__ = cause
    return exc


class _CommittedTestMixin:

    databases = {"default"}

    def setUp(self):
        super().setUp()
        self.suffix = uuid.uuid4().hex[:12]
        # Nothing here is rolled back and the test database is kept between runs, so every
        # row these tests commit is removed again, including the side-effect rows below.
        self.notification_ids_before = set(Notifications.objects.values_list("id", flat=True))
        self.user = User.objects.create(username=f"test_tags_{self.suffix}")
        self.product_type = Product_Type.objects.create(name=f"Test Tags PT {self.suffix}")
        self.product = Product.objects.create(
            name=f"Test Tags Product {self.suffix}", description="Test", prod_type=self.product_type,
        )
        self.engagement = Engagement.objects.create(
            name=f"Test Tags Engagement {self.suffix}",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.test_type = Test_Type.objects.create(name=f"Test Tags {self.suffix}")
        self.test = self._create_test()
        self.environment = Development_Environment.objects.create(name=f"Test Tags Env {self.suffix}")
        self.tag_model = Test.tags.tag_model
        self.addCleanup(self._remove_committed_rows)

    def _create_test(self):
        return Test.objects.create(
            engagement=self.engagement,
            test_type=self.test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    def _tag_name(self, label):
        return f"{self.suffix}-{label}"

    def _remove_committed_rows(self):
        for test in Test.objects.filter(engagement=self.engagement):
            test.tags.clear()
        Test.objects.filter(engagement=self.engagement).delete()
        Test_Type.objects.filter(id=self.test_type.id).delete()
        Engagement.objects.filter(id=self.engagement.id).delete()
        Product.objects.filter(id=self.product.id).delete()
        Product_Type.objects.filter(id=self.product_type.id).delete()
        User.objects.filter(id=self.user.id).delete()
        Development_Environment.objects.filter(id=self.environment.id).delete()
        self.tag_model.objects.filter(name__startswith=self.suffix).delete()
        Alerts.objects.filter(title__endswith=self.suffix).delete()
        Notifications.objects.exclude(id__in=self.notification_ids_before).delete()

    def _reimporter(self, tags):
        reimporter = DefaultReImporter(
            close_old_findings=False,
            user=self.user,
            lead=self.user,
            scan_date=None,
            environment=self.environment,
            active=True,
            verified=False,
            scan_type="Acunetix Scan",
            test=self.test,
            tags=tags,
        )
        reimporter.test = self.test
        return reimporter

    def _tags_on_test(self):
        return {tag.name for tag in Test.objects.get(pk=self.test.pk).tags.all()}


# Regression: async reimports failed with "deadlock detected ... while updating tuple (...)
# in relation dojo_tagulous_test_tags" when two imports updated the reference counts of an
# overlapping tag set in different orders.
class TestSetTestTagsLockOrder(_CommittedTestMixin, SimpleTestCase):

    def test_tags_supplied_out_of_order_do_not_deadlock_a_concurrent_tag_writer(self):
        first_name, second_name = self._tag_name("a"), self._tag_name("b")
        # Another test already uses both tags, so the rows exist and nothing deletes them.
        other_test = self._create_test()
        other_test.tags.set([first_name, second_name])
        first_tag = self.tag_model.objects.get(name=first_name)
        second_tag = self.tag_model.objects.get(name=second_name)
        self.assertLess(first_tag.pk, second_tag.pk)

        main_pid = _backend_pid()
        writer_holds_first = threading.Event()
        import_started = threading.Event()
        writer_errors = []

        def lock_first_then_second():
            # A concurrent writer updating the same two count rows in ascending id order.
            try:
                with connection.cursor() as cursor:
                    cursor.execute(f"SET lock_timeout = '{WAIT_TIMEOUT_SECONDS}s'")
                with transaction.atomic():
                    self.tag_model.objects.filter(pk=first_tag.pk).update(count=F("count"))
                    writer_holds_first.set()
                    _wait_for(
                        lambda: import_started.is_set() and _is_waiting_on_a_lock(main_pid),
                        "the import to wait on a tag row",
                    )
                    self.tag_model.objects.filter(pk=second_tag.pk).update(count=F("count"))
            except BaseException as exc:
                writer_errors.append(exc)
            finally:
                connections.close_all()

        writer = threading.Thread(target=lock_first_then_second, daemon=True)
        writer.start()
        self.assertTrue(writer_holds_first.wait(WAIT_TIMEOUT_SECONDS), "the concurrent writer did not start")
        import_started.set()
        # One attempt only: the conflict retry would otherwise hide a deadlock here.
        with mock.patch.object(base_importer, "TEST_TAG_SET_MAX_ATTEMPTS", 1):
            try:
                # Supplied highest id first, the order that used to lock the rows backwards.
                self._reimporter([second_name, first_name]).update_test_tags()
            except OperationalError as exc:
                self.fail(f"setting the test's tags lost a lock conflict: {exc}")
        writer.join(WAIT_TIMEOUT_SECONDS)
        self.assertFalse(writer.is_alive(), "the concurrent writer did not finish")
        self.assertEqual(writer_errors, [], msg=f"the concurrent writer lost a lock conflict: {writer_errors}")
        self.assertEqual({first_name, second_name}, self._tags_on_test())
        for tag in (first_tag, second_tag):
            tag.refresh_from_db()
            self.assertEqual(tag.count, 2, msg=f"{tag.name} is used by both tests")

    def test_replacing_tags_keeps_counts_and_removes_unused_tags(self):
        """Control: the ordered write is still a set(): old tags go, new tags land, counts hold."""
        kept, dropped, added = self._tag_name("kept"), self._tag_name("dropped"), self._tag_name("added")
        self.test.tags.set([kept, dropped])

        self._reimporter([added, kept]).update_test_tags()

        self.assertEqual({kept, added}, self._tags_on_test())
        self.assertEqual(self.tag_model.objects.get(name=kept).count, 1)
        self.assertEqual(self.tag_model.objects.get(name=added).count, 1)
        self.assertFalse(self.tag_model.objects.filter(name=dropped).exists(), "an unused tag is still cleaned up")

    def test_setting_the_same_tags_again_is_stable(self):
        """Control: re-applying a test's only use of a tag must not lose it to tagulous' cleanup."""
        name = self._tag_name("only")
        self.test.tags.set([name])

        self._reimporter([name]).update_test_tags()

        self.assertEqual({name}, self._tags_on_test())
        self.assertEqual(self.tag_model.objects.get(name=name).count, 1)


class TestSetTestTagsConflictRetry(_CommittedTestMixin, SimpleTestCase):

    def test_a_deadlock_is_retried_and_the_tags_land(self):
        real_set = type(self.test.tags).set
        calls = {"n": 0}

        def deadlock_once(manager, tags, *args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise _deadlock_error()
            return real_set(manager, tags, *args, **kwargs)

        with mock.patch.object(type(self.test.tags), "set", autospec=True, side_effect=deadlock_once):
            self._reimporter([self._tag_name("retried")]).update_test_tags()

        self.assertEqual(calls["n"], 2)
        self.assertEqual({self._tag_name("retried")}, self._tags_on_test())

    def test_a_non_transient_operational_error_is_not_retried(self):
        """Control: only deadlocks and serialization failures are retried; anything else surfaces."""
        calls = {"n": 0}

        def statement_timeout(manager, tags, *args, **kwargs):
            calls["n"] += 1
            raise _non_transient_error()

        with (
            mock.patch.object(type(self.test.tags), "set", autospec=True, side_effect=statement_timeout),
            self.assertRaises(OperationalError),
        ):
            self._reimporter([self._tag_name("timeout")]).update_test_tags()
        self.assertEqual(calls["n"], 1)
