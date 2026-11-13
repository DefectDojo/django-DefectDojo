"""
Imports and reimports into one test run one at a time.

A client that times out on a long synchronous reimport and retries it starts a second reimport
into the same test while the first is still running. The two match and write the same finding
rows, and they deadlocked (SQLSTATE 40P01) or had statements cancelled by statement_timeout
(57014). The second one now waits for the first to finish, then runs as it always did; only a
wait longer than DD_SERIALIZE_TEST_IMPORTS_WAIT_SECONDS fails, with a 409.

These run imports on real, separate database connections with committed rows, which a TestCase
cannot do; see test_dedupe_delete_commit_race for the harness they share.
"""

import threading
from contextlib import contextmanager
from unittest.mock import patch

from django.db import connection
from django.test import SimpleTestCase, override_settings
from rest_framework.test import APIClient

from dojo.importers import import_lock
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.importers.import_lock import TEST_IMPORT_TURN_LOCK_CLASS, TestImportInProgress
from dojo.models import Development_Environment, Finding, Test_Import, User
from dojo.tasks import _async_dupe_delete_impl  # noqa: PLC2701
from unittests.test_dedupe_delete_commit_race import (
    WAIT_TIMEOUT_SECONDS,
    _ConcurrentThread,
    _DupeDeleteDuringWriteMixin,
    _import_lock_is_held,
    _wait_for,
)


@contextmanager
def _import_turn_held_elsewhere(test_id):
    """Hold a test's one-import-at-a-time lock on another connection, as an import running in another worker does."""
    held = threading.Event()
    release = threading.Event()

    def hold():
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_lock(%s, %s)", [TEST_IMPORT_TURN_LOCK_CLASS, test_id])
        held.set()
        release.wait(WAIT_TIMEOUT_SECONDS)
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_unlock(%s, %s)", [TEST_IMPORT_TURN_LOCK_CLASS, test_id])

    holder = _ConcurrentThread(hold)
    holder.start()
    if not held.wait(WAIT_TIMEOUT_SECONDS):
        msg = "the other connection never took the lock"
        raise AssertionError(msg)
    try:
        yield
    finally:
        release.set()
        holder.join(WAIT_TIMEOUT_SECONDS)


def _import_turn_holders(test_id):
    """Backend pids holding the test's one-import-at-a-time lock, as any connection sees them."""
    return [pid for _, pid, *_ in import_lock._import_lock_holders([test_id], TEST_IMPORT_TURN_LOCK_CLASS)]


class _SerializedImportMixin(_DupeDeleteDuringWriteMixin):

    """Committed findings, a Generic Findings Import report, and a superuser for the API."""

    # Deduplication is on (the mixin turns it on) but nothing is deleted: these tests are about
    # two imports, not about the delete.
    DELETE_DUPLICATES = False

    def setUp(self):
        super().setUp()
        self.target = self._new_generic_test()

    def _findings_of(self, test):
        return Finding.objects.filter(test=test).count()

    def _api_client(self):
        # The API resolves the environment by name, and these tests commit their rows into a database that may have
        # none yet. The mixin's cleanup removes every row a test committed, this one and the superuser included,
        # after the findings that reference them.
        Development_Environment.objects.get_or_create(name="Development")
        superuser = User.objects.create(username=f"serial_import_su_{self.suffix}", is_superuser=True, is_staff=True)
        client = APIClient()
        client.force_authenticate(user=superuser)
        return client

    def _post_reimport(self, client):
        return client.post("/api/v2/reimport-scan/", {
            "test": self.target.id,
            "scan_type": "Generic Findings Import",
            "file": self._report(),
            "deduplication_execution_mode": "sync",
        }, format="multipart", secure=True)


# Regression: two reimports into one test (a client retrying one it had timed out on) ran at the
# same time and deadlocked on the test's finding rows (40P01), or were cancelled by
# statement_timeout (57014).
@override_settings(SERIALIZE_TEST_IMPORTS_WAIT_SECONDS=WAIT_TIMEOUT_SECONDS)
class TestSecondImportIntoATestWaitsForTheFirst(_SerializedImportMixin, SimpleTestCase):

    """A second import into a test that is being imported waits for the first, then runs as before."""

    def test_second_reimport_waits_for_the_first_and_both_complete(self):
        real_process_findings = DefaultReImporter.process_findings
        entered = []
        first_inside = threading.Event()
        let_the_first_go_on = threading.Event()

        def process_findings_pausing_the_first(importer, *args, **kwargs):
            entered.append(threading.current_thread().name)
            if len(entered) == 1:
                # The first reimport holds the test from here on: it is writing its findings.
                first_inside.set()
                let_the_first_go_on.wait(WAIT_TIMEOUT_SECONDS)
            return real_process_findings(importer, *args, **kwargs)

        real_holders = import_lock._import_lock_holders
        second_found_the_test_taken = threading.Event()

        def holders_seen_by_a_waiting_import(*args, **kwargs):
            second_found_the_test_taken.set()
            return real_holders(*args, **kwargs)

        with (
            patch.object(DefaultReImporter, "process_findings", process_findings_pausing_the_first),
            patch.object(import_lock, "_import_lock_holders", holders_seen_by_a_waiting_import),
            patch.object(import_lock, "TEST_IMPORT_TURN_POLL_SECONDS", 0.05),
        ):
            first = _ConcurrentThread(lambda: self._reimport(self.target))
            first.start()
            _wait_for(first_inside.is_set, "the first reimport to start writing")
            second = _ConcurrentThread(lambda: self._reimport(self.target))
            second.start()
            _wait_for(second_found_the_test_taken.is_set, "the second reimport to find the test being imported")

            self.assertEqual(
                len(entered), 1,
                msg="the second reimport started writing findings while the first was still writing them",
            )
            self.assertTrue(second.is_alive(), msg="the second reimport did not wait for the first")

            let_the_first_go_on.set()
            first.join_or_fail(self)
            second.join_or_fail(self)

        self.assertEqual(len(entered), 2, msg="the second reimport never ran after the first finished")
        self.assertEqual(
            self._findings_of(self.target), self.FINDINGS_IN_REPORT,
            msg="the first reimport creates the report's findings and the second matches them, creating none",
        )
        self.assertEqual(Test_Import.objects.filter(test=self.target).count(), 2, msg="both reimports were recorded")
        self.assertEqual(_import_turn_holders(self.target.id), [], msg="a reimport left the test locked")

    def test_reimports_one_after_another_are_unchanged(self):
        self._reimport(self.target)
        self.assertEqual(_import_turn_holders(self.target.id), [], msg="the first reimport left the test locked")
        self._reimport(self.target)

        self.assertEqual(self._findings_of(self.target), self.FINDINGS_IN_REPORT)
        self.assertEqual(Test_Import.objects.filter(test=self.target).count(), 2)
        self.assertEqual(_import_turn_holders(self.target.id), [], msg="the second reimport left the test locked")

    def test_a_failed_reimport_releases_the_test(self):
        def fail(*_args, **_kwargs):
            msg = "boom"
            raise RuntimeError(msg)

        with patch.object(DefaultReImporter, "process_findings", fail), self.assertRaisesMessage(RuntimeError, "boom"):
            self._reimport(self.target)

        self.assertEqual(_import_turn_holders(self.target.id), [], msg="the failed reimport left the test locked")
        self._reimport(self.target)  # and the next one runs at once
        self.assertEqual(self._findings_of(self.target), self.FINDINGS_IN_REPORT)

    def test_a_reimport_into_another_test_does_not_wait(self):
        with _import_turn_held_elsewhere(self.target.id):
            other = self._new_generic_test()
            self._reimport(other)

        self.assertEqual(self._findings_of(other), self.FINDINGS_IN_REPORT)


@override_settings(SERIALIZE_TEST_IMPORTS_WAIT_SECONDS=1)
class TestImportThatWaitsTooLongIsRefused(_SerializedImportMixin, SimpleTestCase):

    """A wait longer than DD_SERIALIZE_TEST_IMPORTS_WAIT_SECONDS fails with 409, and changes nothing."""

    def test_reimport_scan_answers_409_naming_the_test(self):
        client = self._api_client()

        with _import_turn_held_elsewhere(self.target.id):
            response = self._post_reimport(client)

        self.assertEqual(response.status_code, 409, msg=response.content[:800])
        self.assertIn(f"test {self.target.id} is still running", response.json()["detail"])
        self.assertEqual(self._findings_of(self.target), 0, msg="the refused reimport imported findings")
        self.assertEqual(Test_Import.objects.filter(test=self.target).count(), 0)
        self.assertFalse(_import_lock_is_held(self.target.id), msg="the refused reimport kept the test locked")

    def test_reimport_scan_succeeds_once_the_other_import_has_finished(self):
        client = self._api_client()

        with _import_turn_held_elsewhere(self.target.id):
            pass
        response = self._post_reimport(client)

        self.assertEqual(response.status_code, 201, msg=response.content[:800])
        self.assertEqual(self._findings_of(self.target), self.FINDINGS_IN_REPORT)

    @override_settings(SERIALIZE_TEST_IMPORTS_WAIT_SECONDS=0)
    def test_zero_refuses_at_once(self):
        with _import_turn_held_elsewhere(self.target.id), self.assertRaises(TestImportInProgress) as raised:
            self._reimport(self.target)

        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("waited 0 seconds", str(raised.exception))

    @override_settings(SERIALIZE_TEST_IMPORTS=False)
    def test_turned_off_imports_without_waiting(self):
        with _import_turn_held_elsewhere(self.target.id):
            self._reimport(self.target)

        self.assertEqual(self._findings_of(self.target), self.FINDINGS_IN_REPORT)

    def test_an_abandoned_lock_does_not_hold_the_import_back(self):
        # Every holder idle for longer than the threshold is a lock left behind (a pooler, a host
        # that died), as for the duplicate delete: the import goes ahead as it did before the lock.
        with (
            _import_turn_held_elsewhere(self.target.id),
            patch.object(import_lock, "_abandoned_threshold_seconds", return_value=0.001),
            self.assertLogs(import_lock.logger, level="WARNING") as logs,
        ):
            self._reimport(self.target)

        self.assertEqual(self._findings_of(self.target), self.FINDINGS_IN_REPORT)
        self.assertIn("without waiting for the import lock", "\n".join(logs.output))


@override_settings(SERIALIZE_TEST_IMPORTS_WAIT_SECONDS=WAIT_TIMEOUT_SECONDS)
class TestTryingForTheTestWithoutWaiting(_SerializedImportMixin, SimpleTestCase):

    """
    A caller that must not block (a background import in a worker, which re-queues itself instead) asks for the
    test's turn with wait_seconds=0, whatever DD_SERIALIZE_TEST_IMPORTS_WAIT_SECONDS says.
    """

    def test_wait_seconds_zero_refuses_at_once(self):
        importer = DefaultReImporter(test=self.target, **self._options())
        with (
            _import_turn_held_elsewhere(self.target.id),
            importer.import_lock_scope(),
            self.assertRaises(TestImportInProgress) as raised,
        ):
            importer.lock_test_under_import(self.target, wait_seconds=0)

        self.assertIn("waited 0 seconds", str(raised.exception))
        self.assertEqual(_import_turn_holders(self.target.id), [], msg="the refused import kept something locked")

    def test_the_turn_taken_up_front_is_the_one_process_scan_keeps(self):
        importer = DefaultReImporter(test=self.target, **self._options())
        real_wait = import_lock.wait_for_test_import_turn
        asked = []

        def counting_wait(test_id, *args, **kwargs):
            asked.append(test_id)
            return real_wait(test_id, *args, **kwargs)

        with patch("dojo.importers.base_importer.wait_for_test_import_turn", counting_wait), importer.import_lock_scope():
            importer.lock_test_under_import(self.target, wait_seconds=0)
            importer.process_scan(self._report())

        self.assertEqual(asked, [self.target.id], msg="process_scan asked for a turn its importer already had")
        self.assertEqual(self._findings_of(self.target), self.FINDINGS_IN_REPORT)
        self.assertEqual(_import_turn_holders(self.target.id), [], msg="the import left the test locked")

    def test_a_test_whose_lock_was_left_behind_is_not_asked_for_again(self):
        importer = DefaultReImporter(test=self.target, **self._options())
        asked = []

        def abandoned(test_id, *_args, **_kwargs):
            asked.append(test_id)
            return False  # not taken: turned off, or the holder is gone

        with patch("dojo.importers.base_importer.wait_for_test_import_turn", abandoned), importer.import_lock_scope():
            importer.lock_test_under_import(self.target, wait_seconds=0)
            importer.lock_test_under_import(self.target)

        self.assertEqual(asked, [self.target.id], msg="the second call waited again, in a worker that must not wait")


@override_settings(DUPE_DELETE_GRACE_MINUTES=0, DUPE_DELETE_MAX_PER_RUN=1_000_000)
class TestDupeDeleteIgnoresTheImportTurnLock(_SerializedImportMixin, SimpleTestCase):

    """The one-import-at-a-time lock is its own key: the duplicate delete reads only the import lock, as before."""

    DELETE_DUPLICATES = True

    def test_duplicates_of_a_test_held_only_by_the_turn_lock_are_deleted(self):
        self._import()  # the originals
        duplicates_test = self._import()
        duplicates = set(Finding.objects.filter(test=duplicates_test, duplicate=True).values_list("id", flat=True))
        self.assertEqual(len(duplicates), self.FINDINGS_IN_REPORT, msg="setup: the second import is all duplicates")

        with _import_turn_held_elsewhere(duplicates_test.id):
            self.assertFalse(_import_lock_is_held(duplicates_test.id), msg="the turn lock reads as the import lock")
            deleter = _ConcurrentThread(_async_dupe_delete_impl)
            deleter.start()
            deleter.join_or_fail(self)

        self.assertFalse(
            Finding.objects.filter(id__in=duplicates).exists(),
            msg="the delete kept the duplicates of a test that only the turn lock was held on",
        )
