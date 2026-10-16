"""
Concurrency tests for the ``duplicate_finding`` self-FK between deduplication and bulk delete.

The self-FK is ON DELETE DO_NOTHING and DEFERRABLE INITIALLY DEFERRED, so a dangling link
is only rejected at COMMIT. Two code paths guard it, each with a read-then-write step:

* deduplication (``_flush_duplicate_changes``) drops links to originals that no longer
  exist, then writes the rest;
* the chunked bulk delete (``bulk_delete_findings``) re-points or promotes findings that
  still point into the chunk, then deletes the chunk.

Neither check held a lock, so a concurrent transaction could invalidate it between the
read and the COMMIT. These tests reproduce both interleavings with two real database
connections and real commits. A ``TestCase`` cannot do this: it runs each test inside one
transaction that is rolled back, so a deferred constraint is never checked and a second
connection cannot see the test's rows. ``TransactionTestCase`` is not usable in this suite
either (its between-test flush trips over tables that are not in the flush set), so these
tests commit their own rows and remove them afterwards.

The interleaving is forced deterministically: the thread that must go second waits until
the other one has either finished its step or is blocked on a row lock held by the first
(``pg_blocking_pids``). Without the row locks the first case happens and the COMMIT fails;
with them the second case happens and each side sees the other's committed result.
"""

import json
import logging
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

from crum import impersonate
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import DatabaseError, IntegrityError, OperationalError, connection, connections, transaction
from django.test import SimpleTestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from dojo import tasks as dojo_tasks
from dojo.db_utils import is_transient_db_conflict
from dojo.finding import deduplication
from dojo.finding import helper as finding_helper
from dojo.finding.deduplication import _flush_duplicate_changes  # noqa: PLC2701
from dojo.finding.helper import bulk_delete_findings
from dojo.importers import import_lock
from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.importers.import_lock import TEST_IMPORT_LOCK_CLASS
from dojo.models import (
    Alerts,
    Development_Environment,
    Engagement,
    Finding,
    Notifications,
    Product,
    Product_Type,
    System_Settings,
    Test,
    Test_Import,
    Test_Import_Finding_Action,
    Test_Type,
    User,
)
from dojo.tags.utils import bulk_add_tags_to_instances
from dojo.tasks import _async_dupe_delete_impl  # noqa: PLC2701
from dojo.vulnerability.models import Vulnerability

logger = logging.getLogger(__name__)

# Upper bound for any single wait in these tests. A correct run finishes each wait in
# milliseconds; the bound only turns a regression that would hang into a failure.
WAIT_TIMEOUT_SECONDS = 20


def _backend_pid():
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_backend_pid()")
        return cursor.fetchone()[0]


def _is_waiting_on_a_lock(pid):
    """True when backend ``pid`` is blocked on a lock held by another backend."""
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


def _set_lock_timeout():
    # Bounded so a regression surfaces as an error instead of hanging the run.
    with connection.cursor() as cursor:
        cursor.execute(f"SET lock_timeout = '{WAIT_TIMEOUT_SECONDS}s'")


class _ConcurrentThread(threading.Thread):

    """Run ``target`` on its own database connection and keep whatever it raised."""

    def __init__(self, target):
        super().__init__(daemon=True)
        self._target_fn = target
        self.error = None
        self.result = None

    def run(self):
        try:
            _set_lock_timeout()
            self.result = self._target_fn()
        except BaseException as exc:  # reported by join_or_fail, not swallowed
            self.error = exc
        finally:
            connections.close_all()

    def join_or_fail(self, testcase):
        self.join(WAIT_TIMEOUT_SECONDS)
        testcase.assertFalse(self.is_alive(), "the concurrent transaction did not finish")
        if self.error is not None:
            raise self.error


def _integer_keyed_tables():
    """Every table with a single integer primary key, with that key's column."""
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT cls.relname, att.attname
            FROM pg_index AS idx
            JOIN pg_class AS cls ON cls.oid = idx.indrelid
            JOIN pg_namespace AS ns ON ns.oid = cls.relnamespace
            JOIN pg_attribute AS att ON att.attrelid = cls.oid AND att.attnum = idx.indkey[0]
            WHERE idx.indisprimary AND idx.indnatts = 1 AND ns.nspname = current_schema()
              AND att.atttypid IN ('int2'::regtype, 'int4'::regtype, 'int8'::regtype)
            """,
        )
        return cursor.fetchall()


def _high_water_marks():
    """The highest primary key in every integer-keyed table, before a test commits anything."""
    marks = {}
    with connection.cursor() as cursor:
        for table, column in _integer_keyed_tables():
            cursor.execute(f'SELECT COALESCE(MAX("{column}"), 0) FROM "{table}"')
            marks[table, column] = cursor.fetchone()[0]
    return marks


def _delete_rows_added_since(marks):
    """
    Delete every row committed since ``marks``, in every table.

    These tests commit real rows (that is the point of them), and the database is kept between
    test modules, so anything left behind -- a second "Development" environment, a tag, a location,
    a history event -- changes what later tests see. The foreign keys are deferred, so the order of
    the deletes does not matter; deleting audited rows records history events, which the next pass
    removes.
    """
    for _ in range(3):
        deleted = 0
        with transaction.atomic(), connection.cursor() as cursor:
            cursor.execute("SET CONSTRAINTS ALL DEFERRED")
            for (table, column), mark in marks.items():
                cursor.execute(f'DELETE FROM "{table}" WHERE "{column}" > %s', [mark])
                deleted += cursor.rowcount
        if not deleted:
            return


@contextmanager
def _import_lock_held_elsewhere(test_id):
    """Hold a test's import lock on another connection, as an import running in another worker does."""
    held = threading.Event()
    release = threading.Event()

    def hold():
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_lock_shared(%s, %s)", [TEST_IMPORT_LOCK_CLASS, test_id])
        held.set()
        release.wait(WAIT_TIMEOUT_SECONDS)
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_unlock_shared(%s, %s)", [TEST_IMPORT_LOCK_CLASS, test_id])

    holder = _ConcurrentThread(hold)
    holder.start()
    if not held.wait(WAIT_TIMEOUT_SECONDS):
        msg = "the other connection never took the import lock"
        raise AssertionError(msg)
    try:
        yield
    finally:
        release.set()
        holder.join(WAIT_TIMEOUT_SECONDS)


def _import_lock_is_held(test_id):
    """Ask from another connection, as the delete would, whether an import holds this test's lock."""
    def in_a_transaction():
        with transaction.atomic():
            return bool(dojo_tasks.tests_under_import_now({test_id}))

    probe = _ConcurrentThread(in_a_transaction)
    probe.start()
    probe.join(WAIT_TIMEOUT_SECONDS)
    if probe.error is not None:
        raise probe.error
    return probe.result


class _CommittedFindingsMixin:

    """Create committed findings for one test and remove them afterwards."""

    databases = {"default"}

    def setUp(self):
        super().setUp()
        # Registered first so it runs last, after the targeted cleanups below.
        self.addCleanup(_delete_rows_added_since, _high_water_marks())
        suffix = uuid.uuid4().hex[:12]
        self.suffix = suffix
        self.notification_ids_before = set(Notifications.objects.values_list("id", flat=True))
        self.user = User.objects.create(username=f"dedupe_race_{suffix}")
        self.product_type = Product_Type.objects.create(name=f"Dedupe Race PT {suffix}")
        self.product = Product.objects.create(
            name=f"Dedupe Race Product {suffix}",
            description="Test",
            prod_type=self.product_type,
        )
        self.engagement = Engagement.objects.create(
            name=f"Dedupe Race Engagement {suffix}",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.test = Test.objects.create(
            engagement=self.engagement,
            test_type=Test_Type.objects.create(name=f"Dedupe Race {suffix}"),
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.addCleanup(self._remove_committed_rows)
        _set_lock_timeout()
        self.addCleanup(self._reset_lock_timeout)

    @staticmethod
    def _reset_lock_timeout():
        with connection.cursor() as cursor:
            cursor.execute("RESET lock_timeout")

    def _remove_committed_rows(self):
        # Nothing here is rolled back, and later tests in the same kept database count
        # queries, so every row this test committed goes, including the deletion alerts.
        Finding.objects.filter(test=self.test).update(duplicate_finding=None, duplicate=False)
        bulk_delete_findings(Finding.objects.filter(test=self.test))
        test_type_id = self.test.test_type_id
        Test.objects.filter(id=self.test.id).delete()
        Test_Type.objects.filter(id=test_type_id).delete()
        Engagement.objects.filter(id=self.engagement.id).delete()
        Product.objects.filter(id=self.product.id).delete()
        Product_Type.objects.filter(id=self.product_type.id).delete()
        User.objects.filter(id=self.user.id).delete()
        Alerts.objects.filter(title__endswith=self.suffix).delete()
        # Creating the product lazily creates the system-wide notification settings row.
        Notifications.objects.exclude(id__in=self.notification_ids_before).delete()

    def _create_findings(self, *titles):
        # bulk_create keeps Finding.save() side effects (dedupe, grading, hashing) out of
        # rows that are committed for real.
        return Finding.objects.bulk_create([
            Finding(
                test=self.test,
                title=title,
                severity="High",
                numerical_severity="S1",
                description="Test",
                mitigation="Test",
                impact="Test",
                reporter=self.user,
                active=True,
                verified=True,
            )
            for title in titles
        ])

    @staticmethod
    def _mark_as_duplicate_in_memory(new_finding, original):
        """Apply what set_duplicate(save=False) applies, as a batch does before its flush."""
        new_finding.duplicate = True
        new_finding.active = False
        new_finding.verified = False
        new_finding.duplicate_finding = original
        return new_finding

    def assertNoDanglingDuplicateLinks(self):
        dangling = list(
            Finding.objects
            .filter(duplicate_finding_id__isnull=False)
            .exclude(duplicate_finding_id__in=Finding.objects.values("id"))
            .values_list("id", "duplicate_finding_id"),
        )
        self.assertEqual(dangling, [], msg=f"findings pointing at deleted findings: {dangling}")


# Regression: deduplication of an async import failed at COMMIT with "insert or update on
# table dojo_finding violates foreign key constraint dojo_finding_duplicate_finding_id_...
# Key (duplicate_finding_id)=(N) is not present in table dojo_finding" when the matched
# original was deleted after the flush guard checked it and before the flush committed.
class TestDedupeFlushRacesConcurrentDelete(_CommittedFindingsMixin, SimpleTestCase):

    """A dedup flush must not commit a link to an original a concurrent delete removed."""

    def _flush_while_deleting(self, batch, doomed_id):
        """
        Flush ``batch`` while another transaction deletes ``doomed_id``.

        The deleting transaction removes the row first and holds its COMMIT until the flush
        guard has either finished its existence check or is waiting on that row. It then
        commits, so the flush reaches its own COMMIT after the delete is durable.
        """
        main_pid = _backend_pid()
        row_deleted = threading.Event()
        guard_done = threading.Event()

        def delete_then_commit_after_the_guard():
            with transaction.atomic():
                bulk_delete_findings(Finding.objects.filter(id=doomed_id), order_desc=True)
                row_deleted.set()
                _wait_for(
                    lambda: guard_done.is_set() or _is_waiting_on_a_lock(main_pid),
                    "the flush guard to check the originals",
                )

        deleter = _ConcurrentThread(delete_then_commit_after_the_guard)
        real_guard = deduplication._drop_links_to_deleted_originals

        def guard_then_let_the_delete_commit(findings):
            result = real_guard(findings)
            guard_done.set()
            deleter.join_or_fail(self)
            return result

        deleter.start()
        self.assertTrue(row_deleted.wait(WAIT_TIMEOUT_SECONDS), "the concurrent delete did not start")
        with patch.object(deduplication, "_drop_links_to_deleted_originals", guard_then_let_the_delete_commit):
            try:
                flushed = _flush_duplicate_changes(batch)
            except IntegrityError as exc:
                self.fail(f"the flush committed a link to a finding deleted concurrently: {exc}")
        deleter.join_or_fail(self)
        return flushed

    def test_original_deleted_between_guard_and_commit_is_not_linked(self):
        original, surviving_original, loses_link, keeps_link = self._create_findings(
            "Race doomed original", "Race surviving original", "Race loses link", "Race keeps link",
        )
        self._mark_as_duplicate_in_memory(loses_link, original)
        self._mark_as_duplicate_in_memory(keeps_link, surviving_original)

        flushed = self._flush_while_deleting([loses_link, keeps_link], original.id)

        self.assertFalse(Finding.objects.filter(id=original.id).exists(), "the concurrent delete must win")
        loses_link.refresh_from_db()
        self.assertIsNone(
            loses_link.duplicate_finding_id,
            msg=f"a link to the deleted original must not be written, persisted={loses_link.duplicate_finding_id}",
        )
        self.assertFalse(loses_link.duplicate, "the finding stays as it was rather than a duplicate of nothing")
        self.assertTrue(loses_link.active, "the finding keeps the status it had before the unusable match")
        keeps_link.refresh_from_db()
        self.assertEqual(
            keeps_link.duplicate_finding_id, surviving_original.id,
            msg=f"the rest of the batch must still be deduplicated, persisted={keeps_link.duplicate_finding_id}",
        )
        self.assertEqual([finding.id for finding in flushed], [keeps_link.id])
        self.assertNoDanglingDuplicateLinks()

    def test_concurrent_delete_of_an_unrelated_finding_leaves_the_flush_alone(self):
        """Control: a delete that no link depends on changes nothing about the flush."""
        original, unrelated, duplicate = self._create_findings(
            "Race control original", "Race control unrelated", "Race control duplicate",
        )
        self._mark_as_duplicate_in_memory(duplicate, original)

        flushed = self._flush_while_deleting([duplicate], unrelated.id)

        duplicate.refresh_from_db()
        self.assertEqual(
            duplicate.duplicate_finding_id, original.id,
            msg=f"the link should have been persisted, persisted={duplicate.duplicate_finding_id}",
        )
        self.assertTrue(duplicate.duplicate)
        self.assertEqual([finding.id for finding in flushed], [duplicate.id])
        self.assertNoDanglingDuplicateLinks()


# Regression: the excess-duplicate delete task (async_dupe_delete) failed at COMMIT with
# "update or delete on table dojo_finding violates foreign key constraint
# dojo_finding_duplicate_finding_id_... Key (id)=(N) is still referenced from table
# dojo_finding" when a concurrent import's dedup linked a finding to N after the chunk had
# resolved N's inbound references and before the chunk committed.
class TestBulkDeleteRacesConcurrentDedupeFlush(_CommittedFindingsMixin, SimpleTestCase):

    """A chunk delete must not commit while a concurrent flush links a survivor into it."""

    def _delete_while_flushing(self, doomed_ids, batch):
        """
        Bulk delete ``doomed_ids`` while another transaction flushes ``batch``.

        The flush starts once the chunk has resolved its inbound references, the read the
        chunk's delete relies on. The chunk then waits until the flush has either committed
        or is blocked on a row the chunk holds, and only then deletes and commits.
        """
        writer_pid = {}
        writer_ready = threading.Event()
        references_resolved = threading.Event()
        writer_done = threading.Event()

        def flush_after_the_chunk_resolved_its_references():
            writer_pid["pid"] = _backend_pid()
            writer_ready.set()
            try:
                if not references_resolved.wait(WAIT_TIMEOUT_SECONDS):
                    msg = "the chunk never resolved its inbound references"
                    raise AssertionError(msg)
                return _flush_duplicate_changes(batch)
            finally:
                writer_done.set()

        writer = _ConcurrentThread(flush_after_the_chunk_resolved_its_references)
        real_resolve = finding_helper.resolve_inbound_duplicate_references

        def resolve_then_let_the_flush_run(chunk_ids, delete_scope_ids):
            result = real_resolve(chunk_ids, delete_scope_ids)
            references_resolved.set()
            _wait_for(
                lambda: writer_done.is_set() or _is_waiting_on_a_lock(writer_pid["pid"]),
                "the concurrent flush to commit or block on the chunk",
            )
            return result

        writer.start()
        self.assertTrue(writer_ready.wait(WAIT_TIMEOUT_SECONDS), "the concurrent flush did not start")
        with patch.object(finding_helper, "resolve_inbound_duplicate_references", resolve_then_let_the_flush_run):
            try:
                bulk_delete_findings(Finding.objects.filter(id__in=doomed_ids), order_desc=True)
            except IntegrityError as exc:
                self.fail(f"the chunk committed while a survivor still pointed into it: {exc}")
            finally:
                references_resolved.set()
        writer.join_or_fail(self)
        return writer.result

    def test_link_written_after_resolve_does_not_fail_the_chunk(self):
        doomed, newcomer = self._create_findings("Race doomed finding", "Race newcomer")
        # The concurrent import matched ``doomed`` while it still looked like an original.
        self._mark_as_duplicate_in_memory(newcomer, doomed)

        flushed = self._delete_while_flushing([doomed.id], [newcomer])

        self.assertFalse(Finding.objects.filter(id=doomed.id).exists(), "the chunk must still be deleted")
        newcomer.refresh_from_db()
        self.assertIsNone(
            newcomer.duplicate_finding_id,
            msg=f"no survivor may point at the deleted finding, persisted={newcomer.duplicate_finding_id}",
        )
        self.assertFalse(newcomer.duplicate, "the survivor is left an original, not a duplicate of nothing")
        self.assertEqual(flushed, [], "the flush reports that it wrote nothing")
        self.assertNoDanglingDuplicateLinks()

    def test_concurrent_link_to_a_surviving_original_is_kept(self):
        """Control: a flush that links to a finding outside the chunk is unaffected."""
        doomed, survivor, newcomer = self._create_findings(
            "Race control doomed", "Race control survivor", "Race control newcomer",
        )
        self._mark_as_duplicate_in_memory(newcomer, survivor)

        flushed = self._delete_while_flushing([doomed.id], [newcomer])

        self.assertFalse(Finding.objects.filter(id=doomed.id).exists())
        newcomer.refresh_from_db()
        self.assertEqual(
            newcomer.duplicate_finding_id, survivor.id,
            msg=f"the link should have been persisted, persisted={newcomer.duplicate_finding_id}",
        )
        self.assertEqual([finding.id for finding in flushed], [newcomer.id])
        self.assertNoDanglingDuplicateLinks()

    def test_flush_holding_its_locks_first_does_not_deadlock_the_chunk(self):
        """
        The flush and the chunk take their row locks in one statement each, in id order.

        Here the flush both re-points a finding inside the chunk and links it to another
        finding inside the chunk, and it locks first. The chunk must queue behind it rather
        than hold one of the rows the flush still has to update (a lock cycle Postgres
        would break by aborting one side with a deadlock error).
        """
        repointed, original = self._create_findings("Race lock order repointed", "Race lock order original")
        self.assertLess(repointed.id, original.id)
        self._mark_as_duplicate_in_memory(repointed, original)
        main_pid = _backend_pid()
        flush_locked = threading.Event()
        chunk_done = threading.Event()
        real_guard = deduplication._drop_links_to_deleted_originals

        def guard_then_wait_for_the_chunk_to_queue(findings):
            result = real_guard(findings)
            flush_locked.set()
            _wait_for(
                lambda: chunk_done.is_set() or _is_waiting_on_a_lock(main_pid),
                "the chunk to queue behind the flush",
            )
            return result

        # The chunk's conflict retry would quietly absorb a deadlock; switch it off so one
        # surfaces here as the OperationalError it is.
        with (
            patch.object(deduplication, "_drop_links_to_deleted_originals", guard_then_wait_for_the_chunk_to_queue),
            patch.object(finding_helper, "BULK_DELETE_MAX_CONFLICT_RETRIES", 0),
        ):
            writer = _ConcurrentThread(lambda: _flush_duplicate_changes([repointed]))
            writer.start()
            self.assertTrue(flush_locked.wait(WAIT_TIMEOUT_SECONDS), "the flush did not reach its guard")
            try:
                bulk_delete_findings(Finding.objects.filter(id__in=[repointed.id, original.id]))
            except OperationalError as exc:
                self.fail(f"the chunk lost a lock conflict against the flush: {exc}")
            finally:
                chunk_done.set()
            try:
                writer.join_or_fail(self)
            except OperationalError as exc:
                self.fail(f"the flush lost a lock conflict against the chunk: {exc}")

        self.assertFalse(Finding.objects.filter(id__in=[repointed.id, original.id]).exists())
        self.assertNoDanglingDuplicateLinks()


# Regression: the excess-duplicate delete task (async_dupe_delete) failed at COMMIT with
# "update or delete on table dojo_finding violates foreign key constraint
# dojo_finding_found_by_finding_id_..._fk_dojo_finding_id on table dojo_finding_found_by
# Key (id)=(N) is still referenced from table dojo_finding_found_by" when a concurrent
# import committed a found_by row for N after the chunk cleared N's M2M rows.
class TestBulkDeleteRacesConcurrentM2MWriter(_CommittedFindingsMixin, SimpleTestCase):

    """A chunk delete must not commit while a concurrent writer adds an M2M row into it."""

    def _delete_while_adding_found_by(self, doomed_ids, target_finding_id):
        """
        Bulk delete ``doomed_ids`` while another transaction adds a found_by row to ``target_finding_id``.

        The writer starts once the chunk has cleared its M2M through rows. The chunk then waits
        until the writer has either committed or is blocked on a row the chunk holds, and only
        then deletes and commits.
        """
        found_by_type = Test_Type.objects.create(name=f"Dedupe Race found_by {self.suffix}")
        self.addCleanup(Test_Type.objects.filter(id=found_by_type.id).delete)
        through = Finding.found_by.through
        writer_pid = {}
        writer_ready = threading.Event()
        m2m_cleared = threading.Event()
        writer_done = threading.Event()

        def add_found_by_after_the_chunk_cleared_its_m2m():
            writer_pid["pid"] = _backend_pid()
            writer_ready.set()
            try:
                if not m2m_cleared.wait(WAIT_TIMEOUT_SECONDS):
                    msg = "the chunk never cleared its M2M rows"
                    raise AssertionError(msg)
                with transaction.atomic():
                    through.objects.create(finding_id=target_finding_id, test_type_id=found_by_type.id)
            finally:
                writer_done.set()

        writer = _ConcurrentThread(add_found_by_after_the_chunk_cleared_its_m2m)
        real_clear = finding_helper.bulk_clear_finding_m2m

        def clear_then_let_the_writer_run(finding_qs):
            result = real_clear(finding_qs)
            m2m_cleared.set()
            _wait_for(
                lambda: writer_done.is_set() or _is_waiting_on_a_lock(writer_pid["pid"]),
                "the concurrent writer to commit or block on the chunk",
            )
            return result

        writer.start()
        self.assertTrue(writer_ready.wait(WAIT_TIMEOUT_SECONDS), "the concurrent writer did not start")
        with patch.object(finding_helper, "bulk_clear_finding_m2m", clear_then_let_the_writer_run):
            try:
                bulk_delete_findings(Finding.objects.filter(id__in=doomed_ids), order_desc=True)
            except IntegrityError as exc:
                self.fail(f"the chunk committed while an M2M row still pointed into it: {exc}")
            finally:
                m2m_cleared.set()
        writer.join(WAIT_TIMEOUT_SECONDS)
        self.assertFalse(writer.is_alive(), "the concurrent writer did not finish")
        return writer, through

    def test_found_by_row_written_after_the_m2m_clear_does_not_fail_the_chunk(self):
        (doomed,) = self._create_findings("Race doomed found_by")

        writer, through = self._delete_while_adding_found_by([doomed.id], doomed.id)

        self.assertFalse(Finding.objects.filter(id=doomed.id).exists(), "the chunk must still be deleted")
        self.assertFalse(
            through.objects.filter(finding_id=doomed.id).exists(),
            "no found_by row may survive for the deleted finding",
        )
        # The writer queued behind the chunk's row lock and then found its finding gone, so
        # its own insert is the one rejected -- the only outcome consistent with the delete.
        self.assertIsInstance(writer.error, IntegrityError, msg=f"writer outcome: {writer.error!r}")

    def test_found_by_row_for_a_surviving_finding_is_kept(self):
        """Control: an M2M write for a finding outside the chunk is unaffected."""
        doomed, survivor = self._create_findings("Race control doomed found_by", "Race control survivor found_by")

        writer, through = self._delete_while_adding_found_by([doomed.id], survivor.id)

        self.assertIsNone(writer.error, msg=f"the unrelated writer must commit: {writer.error!r}")
        self.assertFalse(Finding.objects.filter(id=doomed.id).exists())
        self.assertTrue(through.objects.filter(finding_id=survivor.id).exists(), "the survivor keeps its found_by row")

    def _delete_while_a_tag_writer_holds_the_tag_row(self, *, commit_after_the_chunks_deadlock_check):
        """
        Bulk delete two tagged findings while bulk_add_tags_to_instances holds their tag's count row.

        bulk_add_tags_to_instances updates a tag's count row before its COMMIT, and only at
        COMMIT does Postgres take FOR KEY SHARE on the finding for the new through row. The
        chunk locks the finding first and then needs that tag row to decrement its count. The
        writer commits only once the chunk is waiting on the tag row, so the two always form a
        cycle, and Postgres breaks it by aborting one of them.

        Postgres does not fix which one. A waiting backend runs the deadlock check once,
        deadlock_timeout after it started waiting, and aborts itself if it finds a cycle. The
        chunk starts waiting first, so when the writer reaches its COMMIT within
        deadlock_timeout the chunk finds the cycle and is the victim. When the writer is later
        than that (a slow or loaded machine), the chunk's one check ran before the cycle
        existed, and the writer is the victim instead. ``commit_after_the_chunks_deadlock_check``
        forces the second order; without it either can happen.

        Returns ``(chunk_attempts, writer_error)`` after asserting what holds for both orders:
        the chunk deletes, no tag through row survives, and the tag count stays consistent.
        """
        tagged_by_writer, already_tagged = self._create_findings("Race tag writer target", "Race tag writer peer")
        finding_ids = [tagged_by_writer.id, already_tagged.id]
        tag_name = f"race-{self.suffix}"
        already_tagged.tags.add(tag_name)
        tag_model = Finding.tags.tag_model
        self.addCleanup(tag_model.objects.filter(name=tag_name).delete)
        main_pid = _backend_pid()
        with connection.cursor() as cursor:
            cursor.execute("SELECT EXTRACT(EPOCH FROM current_setting('deadlock_timeout')::interval)")
            deadlock_timeout = float(cursor.fetchone()[0])
        writer_holds_tag_row = threading.Event()
        chunk_started = threading.Event()

        def tag_then_commit_once_the_chunk_waits():
            with transaction.atomic():
                bulk_add_tags_to_instances([tag_name], [Finding.objects.get(id=tagged_by_writer.id)])
                writer_holds_tag_row.set()
                _wait_for(
                    lambda: chunk_started.is_set() and _is_waiting_on_a_lock(main_pid),
                    "the chunk to wait on the tag row",
                )
                if commit_after_the_chunks_deadlock_check:
                    # Past the chunk's single deadlock check, which found no cycle yet: from
                    # here only the writer's own check can find it.
                    time.sleep(deadlock_timeout * 2)

        chunk_attempts = []
        real_lock = finding_helper.lock_findings_for_delete

        def count_chunk_attempts(chunk_ids):
            chunk_attempts.append(list(chunk_ids))
            return real_lock(chunk_ids)

        writer = _ConcurrentThread(tag_then_commit_once_the_chunk_waits)
        writer.start()
        self.assertTrue(writer_holds_tag_row.wait(WAIT_TIMEOUT_SECONDS), "the concurrent tag writer did not start")
        chunk_started.set()
        with (
            patch.object(finding_helper, "BULK_DELETE_RETRY_DELAY", 0.01),
            patch.object(finding_helper, "lock_findings_for_delete", count_chunk_attempts),
        ):
            bulk_delete_findings(Finding.objects.filter(id__in=finding_ids))
        writer.join(WAIT_TIMEOUT_SECONDS)
        self.assertFalse(writer.is_alive(), "the concurrent tag writer did not finish")

        writer_was_the_victim = writer.error is not None and is_transient_db_conflict(writer.error)
        if writer.error is not None and not writer_was_the_victim:
            raise writer.error
        chunk_was_the_victim = len(chunk_attempts) > 1
        self.assertNotEqual(
            chunk_was_the_victim,
            writer_was_the_victim,
            f"exactly one side must be the deadlock victim (chunk attempts: {len(chunk_attempts)}, writer: {writer.error!r})",
        )
        self.assertFalse(Finding.objects.filter(id__in=finding_ids).exists(), "the chunk must still be deleted")
        self.assertFalse(
            Finding.tags.through.objects.filter(finding_id__in=finding_ids).exists(),
            "no tag through row may survive for the deleted findings",
        )
        self.assertEqual(tag_model.objects.get(name=tag_name).count, 0, "the tag count matches its remaining uses")
        return chunk_attempts, writer.error

    def test_tag_writer_holding_a_tag_row_does_not_fail_the_chunk(self):
        """
        Lock order against the bulk tag writer, which is the one writer that does not follow it.

        Usually the chunk is the deadlock victim and its conflict retry re-runs it after the
        writer committed, so the writer's through row goes with the chunk. On a slow machine
        the writer can be the victim instead (see the helper). Either way the chunk deletes and
        the tag count stays consistent, and that is what is asserted here.
        """
        self._delete_while_a_tag_writer_holds_the_tag_row(commit_after_the_chunks_deadlock_check=False)

    def test_tag_writer_aborted_as_the_deadlock_victim_leaves_the_chunk_to_finish(self):
        """
        The other order, forced: the writer commits after the chunk's deadlock check.

        Postgres then aborts the writer, whose tag add rolls back, and the chunk takes the tag
        row and commits on its first attempt, with no retry.
        """
        chunk_attempts, writer_error = self._delete_while_a_tag_writer_holds_the_tag_row(
            commit_after_the_chunks_deadlock_check=True,
        )
        self.assertIsNotNone(writer_error, "the writer, not the chunk, must be the deadlock victim")
        self.assertEqual(len(chunk_attempts), 1, "the chunk must not have needed a retry")


# Regression: imports, reimports and POST /api/v2/findings/ failed with "insert or update on
# table <child> violates foreign key constraint ... Key (finding_id)=(N) is not present in table
# dojo_finding" because the excess-duplicate delete task removed a finding that deduplication
# had just marked duplicate while the request or import that created or matched it was still
# writing that finding's child rows (found_by, cwe, tags, locations, companions, ...).
# The per-run cap is lifted so duplicates committed by other tests in the kept database cannot
# crowd this test's own rows out of a run.
@override_settings(DUPE_DELETE_GRACE_MINUTES=1, DUPE_DELETE_MAX_PER_RUN=1_000_000)
class TestDupeDeleteRacesInFlightWriter(_CommittedFindingsMixin, SimpleTestCase):

    """The excess-duplicate delete must leave alone duplicates an import may still be writing to."""

    # The affected configuration: delete every duplicate beyond zero per original.
    DELETE_ALL_DUPLICATES = SimpleNamespace(delete_duplicates=True, max_dupes=0, enable_product_grade=False)

    def _run_dupe_delete(self):
        with patch("dojo.tasks.System_Settings.objects.get", return_value=self.DELETE_ALL_DUPLICATES):
            _async_dupe_delete_impl()

    def _commit_as_duplicate(self, finding, original):
        """Persist what deduplication's flush writes: the duplicate flags and the link, nothing else."""
        Finding.objects.filter(id=finding.id).update(
            duplicate=True, active=False, verified=False, duplicate_finding=original,
        )

    def _backdate(self, *, finding_ids, minutes=120):
        past = timezone.now() - timedelta(minutes=minutes)
        Finding.objects.filter(id__in=finding_ids).update(created=past, updated=past)

    def _write_found_by_and_commit(self, finding_id):
        """The writer's next step after deduplication: a child row for the finding, committed."""
        found_by_type = Test_Type.objects.create(name=f"Dupe delete found_by {self.suffix}")
        self.addCleanup(Test_Type.objects.filter(id=found_by_type.id).delete)
        try:
            with transaction.atomic():
                Finding.found_by.through.objects.create(finding_id=finding_id, test_type_id=found_by_type.id)
        except IntegrityError as exc:
            self.fail(f"the writer's child row was rejected because the finding was deleted under it: {exc}")

    def test_new_duplicate_survives_while_its_import_is_still_writing(self):
        """A finding created and marked duplicate moments ago is not deleted before its writer finishes."""
        original, new_duplicate = self._create_findings("Dupe delete original", "Dupe delete new duplicate")
        self._backdate(finding_ids=[original.id])  # only the duplicate itself is fresh
        self._commit_as_duplicate(new_duplicate, original)

        self._run_dupe_delete()  # the per-minute beat task fires between dedupe and the child write

        self._write_found_by_and_commit(new_duplicate.id)
        self.assertTrue(
            Finding.objects.filter(id=new_duplicate.id).exists(),
            msg="a duplicate created and marked moments ago was deleted while its import was still writing it",
        )

    def test_matched_duplicate_survives_while_its_test_is_being_imported(self):
        """An old finding a reimport matched and deduplication newly marked duplicate is not deleted mid-import."""
        original, matched = self._create_findings("Dupe delete original", "Dupe delete matched duplicate")
        self._commit_as_duplicate(matched, original)
        self._backdate(finding_ids=[original.id, matched.id])  # both rows are old ...

        with _import_lock_held_elsewhere(self.test.id):  # ... but an import is running on their test
            self._run_dupe_delete()

        self._write_found_by_and_commit(matched.id)
        persisted = Finding.objects.filter(id=matched.id).first()
        self.assertIsNotNone(persisted, msg="a matched duplicate in a test under import was deleted mid-import")

    def test_duplicate_of_a_test_just_reimported_is_deleted_once_the_import_has_ended(self):
        """
        Control, and the reason for the lock: a test reimported every few minutes still has its
        excess duplicates deleted between reimports. Recent import activity alone holds nothing back.
        """
        original, matched = self._create_findings("Dupe delete original", "Dupe delete recently reimported")
        self._commit_as_duplicate(matched, original)
        self._backdate(finding_ids=[original.id, matched.id])
        Test.objects.filter(id=self.test.id).update(updated=timezone.now())  # a reimport finished just now

        self._run_dupe_delete()

        self.assertFalse(
            Finding.objects.filter(id=matched.id).exists(),
            msg="an excess duplicate of a test with no import running was kept because the test was reimported recently",
        )

    def test_settled_duplicate_is_still_deleted(self):
        """Control: a duplicate whose finding has been quiet past the grace period is deleted."""
        original, settled = self._create_findings("Dupe delete original", "Dupe delete settled duplicate")
        self._commit_as_duplicate(settled, original)
        self._backdate(finding_ids=[original.id, settled.id])

        self._run_dupe_delete()

        self.assertFalse(Finding.objects.filter(id=settled.id).exists(), msg="a settled excess duplicate must be deleted")
        self.assertTrue(Finding.objects.filter(id=original.id).exists(), msg="the original is never an excess duplicate")

    @override_settings(DUPE_DELETE_GRACE_MINUTES=0)
    def test_zero_grace_period_restores_immediate_deletion(self):
        """Control: DD_DUPE_DELETE_GRACE_MINUTES=0 keeps the old delete-immediately behaviour available."""
        original, new_duplicate = self._create_findings("Dupe delete original", "Dupe delete immediate duplicate")
        self._commit_as_duplicate(new_duplicate, original)

        self._run_dupe_delete()

        self.assertFalse(Finding.objects.filter(id=new_duplicate.id).exists(), msg="grace 0 must delete at once")

    def _post_process_batch(self, finding, *, delete_duplicates, while_deduplicating):
        """Run a deduplication batch for ``finding``, calling ``while_deduplicating`` in its dedupe step."""
        system_settings = SimpleNamespace(
            delete_duplicates=delete_duplicates, max_dupes=0, enable_deduplication=True,
            false_positive_history=False, enable_product_grade=False,
        )
        with (
            patch("dojo.finding.helper.System_Settings.objects.get", return_value=system_settings),
            patch("dojo.importers.import_lock.System_Settings.objects.get", return_value=system_settings),
            patch.object(finding_helper, "dedupe_batch_of_findings", side_effect=lambda _: while_deduplicating()),
        ):
            finding_helper.post_process_findings_batch(
                [finding.id], dedupe_option=True, rules_option=False, product_grading_option=False,
                issue_updater_option=False,
            )

    def test_deduplication_batch_holds_the_import_lock_while_it_runs(self):
        """A deduplication batch keeps the delete off its test until the batch is done, and no longer."""
        (finding,) = self._create_findings("Dupe delete batch lock")
        seen = []

        self._post_process_batch(
            finding, delete_duplicates=True, while_deduplicating=lambda: seen.append(_import_lock_is_held(self.test.id)),
        )

        self.assertEqual(seen, [True], msg="the batch did not hold its test's import lock while deduplicating")
        self.assertFalse(_import_lock_is_held(self.test.id), msg="the batch left its test locked after it finished")

    def test_deduplication_batch_takes_no_lock_when_duplicate_deletion_is_off(self):
        """Control: with duplicate deletion off (the default) the batch takes no lock."""
        (finding,) = self._create_findings("Dupe delete no batch lock")
        seen = []

        self._post_process_batch(
            finding, delete_duplicates=False, while_deduplicating=lambda: seen.append(_import_lock_is_held(self.test.id)),
        )

        self.assertEqual(seen, [False], msg="the batch locked its test although duplicate deletion is off")


# Regression guard: the import lock must never outlive the import that took it. A lock nobody
# releases would keep the excess-duplicate delete off that test for good, so each way one could
# be left behind is bounded: a release that fails drops its connection, a release that finds no
# lock (a pooler in transaction mode) says so, and a lock whose holder has sat idle far longer
# than any import would is treated as abandoned.
@override_settings(DUPE_DELETE_GRACE_MINUTES=0, DUPE_DELETE_MAX_PER_RUN=1_000_000)
class TestImportLockCannotOutliveItsImport(_CommittedFindingsMixin, SimpleTestCase):

    """No failure leaves a test locked against the excess-duplicate delete for good."""

    DELETE_ALL_DUPLICATES = SimpleNamespace(delete_duplicates=True, max_dupes=0, enable_product_grade=False)

    def _run_dupe_delete(self):
        with patch("dojo.tasks.System_Settings.objects.get", return_value=self.DELETE_ALL_DUPLICATES):
            _async_dupe_delete_impl()

    def _old_excess_duplicate(self):
        original, duplicate = self._create_findings("Abandoned lock original", "Abandoned lock duplicate")
        past = timezone.now() - timedelta(minutes=120)
        Finding.objects.filter(id=duplicate.id).update(duplicate=True, active=False, duplicate_finding=original)
        Finding.objects.filter(id__in=[original.id, duplicate.id]).update(created=past, updated=past)
        return duplicate

    def test_a_release_that_fails_drops_the_connection_and_the_lock_with_it(self):
        """
        An import whose transaction aborted cannot run the release. The lock must go when the request
        or task ends, even on a connection Django would otherwise keep open indefinitely.
        """
        with patch.object(import_lock, "import_lock_enabled", return_value=True):
            locked = import_lock.lock_tests_under_import([self.test.id])
        self.assertTrue(_import_lock_is_held(self.test.id), msg="setup: the import holds its test's lock")
        connection.close_at = None  # a persistent connection (CONN_MAX_AGE=None) is never closed for its age

        with transaction.atomic():
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1 / 0")  # the error that aborts the import's transaction
            except DatabaseError:
                pass
            import_lock.unlock_tests_under_import(locked)  # cannot run in an aborted transaction
            transaction.set_rollback(True)
        connection.close_if_unusable_or_obsolete()  # what Django and Celery run after every request and task

        self.assertFalse(
            _import_lock_is_held(self.test.id),
            msg="a failed release left the import lock held on a connection that stays open",
        )

    def test_a_release_that_finds_no_lock_says_how_to_fix_it(self):
        """Behind a pooler in transaction mode the release runs on another server connection and finds nothing."""
        with self.assertLogs(import_lock.logger, level="ERROR") as logs:
            import_lock.unlock_tests_under_import([self.test.id])  # never locked on this connection
        self.assertIn("DD_DUPE_DELETE_SKIP_TESTS_UNDER_IMPORT", "\n".join(logs.output))

    @override_settings(DUPE_DELETE_ABANDONED_IMPORT_LOCK_MINUTES=0.001)
    def test_duplicates_are_deleted_when_the_lock_holder_has_been_idle_too_long(self):
        """A lock whose holder has done nothing for longer than any import would is not an import running."""
        duplicate = self._old_excess_duplicate()

        with _import_lock_held_elsewhere(self.test.id):
            time.sleep(0.5)  # the holder's connection sits idle past the (shortened) threshold
            self._run_dupe_delete()

            self.assertFalse(
                Finding.objects.filter(id=duplicate.id).exists(),
                msg="an abandoned import lock kept the excess-duplicate delete off the test",
            )

    @override_settings(DUPE_DELETE_ABANDONED_IMPORT_LOCK_MINUTES=30)
    def test_duplicates_are_kept_while_the_lock_holder_is_within_the_threshold(self):
        """Control: a holder idle for less than the threshold is an import between statements."""
        duplicate = self._old_excess_duplicate()

        with _import_lock_held_elsewhere(self.test.id):
            time.sleep(0.5)
            self._run_dupe_delete()

            self.assertTrue(
                Finding.objects.filter(id=duplicate.id).exists(),
                msg="the duplicate of a test whose import is running was deleted",
            )


class _DupeDeleteDuringWriteMixin(_CommittedFindingsMixin):

    """
    Run a real import, reimport or finding create while the excess-duplicate delete fires.

    The delete task runs on its own per-minute schedule, so in production it can land at any
    point of an import. These tests make it land at the worst one, every time: right after
    deduplication has committed a batch's duplicate flags, while the writer still has that
    batch's child rows to write. That is the interleaving behind the reported failures, and
    with max_dupes=0 every duplicate the batch produced is a deletion candidate.
    """

    FINDINGS_IN_REPORT = 3
    DELETE_DUPLICATES = True
    IMPORT_TAGS = ()

    def setUp(self):
        super().setUp()
        self.addCleanup(self._remove_imported_rows)
        system_settings = System_Settings.objects.get(no_cache=True)
        previous = (system_settings.enable_deduplication, system_settings.delete_duplicates, system_settings.max_dupes)
        system_settings.enable_deduplication = True
        system_settings.delete_duplicates = self.DELETE_DUPLICATES
        system_settings.max_dupes = 0
        system_settings.save()
        self.addCleanup(self._restore_system_settings, previous)
        self.deleted_by_dupe_delete = []

    @staticmethod
    def _restore_system_settings(previous):
        system_settings = System_Settings.objects.get(no_cache=True)
        (system_settings.enable_deduplication, system_settings.delete_duplicates, system_settings.max_dupes) = previous
        system_settings.save()

    def _remove_imported_rows(self):
        engagement_findings = Finding.objects.filter(test__engagement=self.engagement)
        engagement_findings.update(duplicate_finding=None, duplicate=False)
        bulk_delete_findings(engagement_findings)
        Test.objects.filter(engagement=self.engagement).exclude(id=self.test.id).delete()
        Vulnerability.objects.filter(vulnerability_id__endswith=self.suffix.upper()).delete()

    def _report(self):
        """A Generic Findings Import report whose findings carry the child rows customers lose."""
        return SimpleUploadedFile("report.json", json.dumps({"findings": [
            {
                "title": f"Dupe delete during import {i} {self.suffix}",
                "severity": "High",
                "description": f"Vulnerable component {i}",
                "mitigation": "Upgrade",
                "cwe": 79,
                "vulnerability_ids": [f"CVE-2026-{1000 + i}-{self.suffix.upper()}"],
                "component_name": f"pkg-{i}",
                "component_version": "1.0.0",
                "file_path": f"src/file_{i}.py",
                "line": i + 1,
                "tags": ["dupe-delete-race"],
                "endpoints": [{"host": f"host{i}.example.com", "protocol": "https", "port": 443}],
            }
            for i in range(self.FINDINGS_IN_REPORT)
        ]}).encode(), content_type="application/json")

    def _options(self):
        return {
            "user": self.user, "lead": self.user, "scan_date": None, "active": True, "verified": False,
            "environment": Development_Environment.objects.get_or_create(name="Development")[0],
            "scan_type": "Generic Findings Import", "close_old_findings": False,
            # Deduplicate inline, as the background importer does, so the delete lands inside
            # the import rather than after it.
            "deduplication_execution_mode": "sync",
            **({"tags": list(self.IMPORT_TAGS), "apply_tags_to_findings": True, "apply_tags_to_endpoints": True}
               if self.IMPORT_TAGS else {}),
        }

    def _import(self):
        test, *_ = DefaultImporter(engagement=self.engagement, **self._options()).process_scan(self._report())
        return test

    def _reimport(self, test):
        test, *_ = DefaultReImporter(test=test, **self._options()).process_scan(self._report())
        return test

    def _new_generic_test(self):
        return Test.objects.create(
            engagement=self.engagement,
            test_type=Test_Type.objects.get_or_create(name="Generic Findings Import")[0],
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    @contextmanager
    def _dupe_delete_fires_after(self, module, name):
        """Run the excess-duplicate delete each time ``module.name`` (a deduplication step) returns."""
        real = getattr(module, name)

        def deduplicate_then_delete_excess_duplicates(*args, **kwargs):
            result = real(*args, **kwargs)
            before = set(Finding.objects.filter(test__engagement=self.engagement).values_list("id", flat=True))
            # On its own connection, as the beat task runs in another worker: the import lock is
            # per connection, so a delete on the import's own connection would not see it.
            deleter = _ConcurrentThread(_async_dupe_delete_impl)
            deleter.start()
            deleter.join_or_fail(self)
            after = set(Finding.objects.filter(test__engagement=self.engagement).values_list("id", flat=True))
            self.deleted_by_dupe_delete.extend(sorted(before - after))
            return result

        with patch.object(module, name, deduplicate_then_delete_excess_duplicates):
            yield


# Regression: a reimport (POST /api/v2/reimport-scan/, and the background reimport task that runs
# the same importer) failed with "insert or update on table dojo_endpoint_status /
# dojo_locationfindingreference / pro_enhanced_finding / dojo_finding_tags ... Key (finding_id)=(N)
# is not present in table dojo_finding", or silently lost its import history, when the
# excess-duplicate delete removed findings the import had just deduplicated.
# The grace period is off, so the import lock alone has to protect the run.
@override_settings(DUPE_DELETE_GRACE_MINUTES=0, DUPE_DELETE_MAX_PER_RUN=1_000_000)
class TestImportRacesDupeDelete(_DupeDeleteDuringWriteMixin, SimpleTestCase):

    """An import or reimport must complete with every finding and history row when dupe-delete fires mid-run."""

    def _assert_import_completed(self, run, kind):
        try:
            with self._dupe_delete_fires_after(finding_helper, "dedupe_batch_of_findings"):
                test = run()
        except IntegrityError as exc:
            self.fail(
                f"the {kind} failed because the excess-duplicate delete removed findings it was still "
                f"writing (deleted mid-run: {self.deleted_by_dupe_delete}): {exc}",
            )
        findings = list(Finding.objects.filter(test=test).values_list("id", "duplicate"))
        self.assertEqual(
            len(findings), self.FINDINGS_IN_REPORT,
            msg=f"{kind} persisted {findings}; deleted mid-run: {self.deleted_by_dupe_delete}",
        )
        self.assertTrue(all(duplicate for _, duplicate in findings), msg=f"every finding is a duplicate: {findings}")
        latest_import = Test_Import.objects.filter(test=test).order_by("-id").first()
        recorded = Test_Import_Finding_Action.objects.filter(test_import=latest_import).count()
        self.assertEqual(
            recorded, self.FINDINGS_IN_REPORT,
            msg=f"{kind} recorded {recorded} import-history rows for {self.FINDINGS_IN_REPORT} findings; "
            f"deleted mid-run: {self.deleted_by_dupe_delete}",
        )

    def test_reimport_completes_when_dupe_delete_fires_after_its_deduplication(self):
        self._import()  # the originals
        target = self._new_generic_test()
        self._assert_import_completed(lambda: self._reimport(target), "reimport")

    def test_import_completes_when_dupe_delete_fires_after_its_deduplication(self):
        self._import()  # the originals
        self._assert_import_completed(self._import, "import")

    def test_reimport_matching_existing_duplicates_completes_when_dupe_delete_fires_before_its_batch_flush(self):
        """
        The shape of the synchronous reimport 500s: the reimport matches findings already in its
        test that are duplicates, buffers their endpoint/location statuses and vulnerability ids,
        and the delete removes them before the batch flush writes those rows.
        """
        self._import()  # the originals
        target = self._new_generic_test()
        self._reimport(target)  # its findings are now duplicates, kept by the reimport that made them
        matched = set(Finding.objects.filter(test=target).values_list("id", flat=True))
        self.assertEqual(len(matched), self.FINDINGS_IN_REPORT, msg="setup: the target test holds the duplicates")

        try:
            with self._dupe_delete_fires_after(DefaultReImporter, "process_matched_finding"):
                self._reimport(target)
        except IntegrityError as exc:
            self.fail(
                f"the reimport failed because the excess-duplicate delete removed matched findings "
                f"(deleted mid-run: {self.deleted_by_dupe_delete}): {exc}",
            )
        survivors = set(Finding.objects.filter(test=target).values_list("id", flat=True))
        self.assertEqual(
            survivors, matched,
            msg=f"matched findings deleted mid-reimport: {sorted(matched - survivors)}",
        )


# Regression (follow-up to the grace window): a reimport into a test that had been idle past the
# grace period matched that test's settled duplicates while an excess-duplicate delete run that
# had already selected them was still going, and failed at its batch flush with the same
# "Key (finding_id)=(N) is not present in table dojo_finding". The delete must re-check, under a
# lock, that no import has started on each candidate's test, and the reimport must take its
# test's import lock before it matches anything.
@override_settings(DUPE_DELETE_GRACE_MINUTES=0, DUPE_DELETE_MAX_PER_RUN=1_000_000)
class TestReimportStartRacesDupeDeleteSelection(_DupeDeleteDuringWriteMixin, SimpleTestCase):

    """A delete run's stale selection must not remove duplicates a reimport that started since has matched."""

    def test_reimport_matching_settled_duplicates_selected_by_a_running_delete_completes(self):
        self._import()  # the originals
        target = self._new_generic_test()
        self._reimport(target)  # the duplicates
        settled = set(Finding.objects.filter(test=target).values_list("id", flat=True))
        past = timezone.now() - timedelta(minutes=120)
        Finding.objects.filter(id__in=settled).update(created=past, updated=past)

        selected = threading.Event()
        release = threading.Event()
        real_delete = dojo_tasks._delete_excess_duplicates

        def delete_once_the_reimport_has_started(*args, **kwargs):
            selected.set()
            if not release.wait(WAIT_TIMEOUT_SECONDS):
                msg = "the reimport never reached its first matched finding"
                raise AssertionError(msg)
            return real_delete(*args, **kwargs)

        deleter = _ConcurrentThread(_async_dupe_delete_impl)
        real_match = DefaultReImporter.process_matched_finding

        def match_then_let_the_delete_run(importer, *args, **kwargs):
            if not release.is_set():
                release.set()
                deleter.join_or_fail(self)
            return real_match(importer, *args, **kwargs)

        with (
            patch.object(dojo_tasks, "_delete_excess_duplicates", delete_once_the_reimport_has_started),
            patch.object(DefaultReImporter, "process_matched_finding", match_then_let_the_delete_run),
        ):
            deleter.start()
            self.assertTrue(selected.wait(WAIT_TIMEOUT_SECONDS), "the delete run never selected its candidates")
            try:
                self._reimport(target)
            except IntegrityError as exc:
                self.fail(f"the reimport failed because a delete run removed the duplicates it matched: {exc}")
            finally:
                release.set()
        deleter.join_or_fail(self)

        survivors = set(Finding.objects.filter(test=target).values_list("id", flat=True))
        self.assertEqual(survivors, settled, msg=f"matched duplicates deleted: {sorted(settled - survivors)}")

    def test_settled_duplicates_of_an_idle_test_are_still_deleted_by_a_run(self):
        """Control: with no reimport in between, the same selection is deleted."""
        self._import()
        target = self._new_generic_test()
        self._reimport(target)
        settled = set(Finding.objects.filter(test=target).values_list("id", flat=True))
        past = timezone.now() - timedelta(minutes=120)
        Finding.objects.filter(id__in=settled).update(created=past, updated=past)

        _async_dupe_delete_impl()

        self.assertFalse(Finding.objects.filter(id__in=settled).exists(), msg="settled duplicates must be deleted")


# Regression: a reimport whose target test was deleted while it ran (by a user, or a delete
# cascading from its engagement or product) failed with a raw "insert or update on table ...
# Key (finding_id)=(N) is not present in table dojo_finding" 500 instead of the import's clear
# "was deleted while the scan was being processed" error.
class TestReimportRacesTargetTestDelete(_DupeDeleteDuringWriteMixin, SimpleTestCase):

    """A reimport whose test is deleted mid-run reports that, not a foreign-key error."""

    def test_reimport_reports_its_test_was_deleted(self):
        self._import()
        target = self._new_generic_test()
        self._reimport(target)
        target_id = target.id
        real_match = DefaultReImporter.process_matched_finding
        deleted = threading.Event()

        def delete_the_test_from_another_connection():
            Test.objects.get(id=target_id).delete()

        def match_then_delete_the_test(importer, *args, **kwargs):
            if not deleted.is_set():
                deleted.set()
                deleter = _ConcurrentThread(delete_the_test_from_another_connection)
                deleter.start()
                deleter.join_or_fail(self)
            return real_match(importer, *args, **kwargs)

        with patch.object(DefaultReImporter, "process_matched_finding", match_then_delete_the_test):
            try:
                self._reimport(target)
            except IntegrityError as exc:
                self.fail(f"the reimport surfaced a raw foreign-key error for its deleted test: {exc}")
            except ValidationError as exc:
                self.assertIn("was deleted while the scan was being processed", str(exc))
            else:
                self.fail("a reimport into a test deleted mid-run must not report success")
        self.assertFalse(Test.objects.filter(id=target_id).exists())


# Regression: an import or reimport carrying tags failed with "insert or update on table
# dojo_finding_tags violates foreign key constraint ... Key (finding_id)=(N) is not present in
# table dojo_finding" when a test was deleted while it ran: the batch's tag rows are written at
# the batch boundary, after the findings they belong to were matched or created, and a delete in
# between leaves the bulk insert pointing at findings that are gone. A delete of a different
# test that shares the import's tags must not fail the import or corrupt the shared tag counts.
class TestTaggedImportRacesTestDelete(_DupeDeleteDuringWriteMixin, SimpleTestCase):

    """Imports with tags against concurrent test deletion: clear errors, consistent tag counts."""

    DELETE_DUPLICATES = False  # isolate test deletion from the excess-duplicate delete
    IMPORT_TAGS = ("shared-race-tag", "team-a")

    def _delete_test_in_another_connection(self, test_id):
        deleter = _ConcurrentThread(lambda: Test.objects.get(id=test_id).delete())
        deleter.start()
        deleter.join_or_fail(self)

    def _assert_reports_deleted_test(self, run, kind):
        try:
            run()
        except IntegrityError as exc:
            self.fail(f"the {kind} surfaced a raw foreign-key error for its deleted test: {exc}")
        except ValidationError as exc:
            self.assertIn("was deleted while the scan was being processed", str(exc), msg=f"{kind}: {exc}")
        else:
            self.fail(f"a {kind} into a test deleted mid-run must not report success")

    def _delete_target_before(self, owner, name, target_id_getter):
        real = getattr(owner, name)
        fired = threading.Event()

        def delete_the_test_then_continue(*args, **kwargs):
            if not fired.is_set():
                fired.set()
                self._delete_test_in_another_connection(target_id_getter())
            return real(*args, **kwargs)

        return patch.object(owner, name, delete_the_test_then_continue)

    def test_reimport_with_import_tags_reports_its_test_deleted_before_the_tag_write(self):
        self._import()
        target = self._new_generic_test()
        self._reimport(target)
        with self._delete_target_before(DefaultReImporter, "apply_import_tags_for_batch", lambda: target.id):
            self._assert_reports_deleted_test(lambda: self._reimport(target), "reimport")
        self.assertFalse(Test.objects.filter(id=target.id).exists())

    def test_reimport_with_parser_tags_reports_its_test_deleted_before_the_tag_write(self):
        import dojo.importers.default_reimporter as reimporter_module  # noqa: PLC0415

        self._import()
        target = self._new_generic_test()
        with self._delete_target_before(reimporter_module, "bulk_apply_parser_tags", lambda: target.id):
            self._assert_reports_deleted_test(lambda: self._reimport(target), "reimport")

    def test_import_with_import_tags_reports_its_test_deleted_before_the_tag_write(self):
        def newest_test_id():
            return Test.objects.filter(engagement=self.engagement).order_by("-id").values_list("id", flat=True).first()

        with self._delete_target_before(DefaultImporter, "apply_import_tags_for_batch", newest_test_id):
            self._assert_reports_deleted_test(self._import, "import")

    def _reimport_with_test_deleted_before_the_location_flush(self):
        from dojo.importers.base_location_manager import LocationHandler  # noqa: PLC0415

        self._import()
        target = self._new_generic_test()
        self._reimport(target)
        with self._delete_target_before(LocationHandler, "persist", lambda: target.id):
            self._assert_reports_deleted_test(lambda: self._reimport(target), "reimport")

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_reimport_reports_its_test_deleted_before_the_location_reference_flush(self):
        """Locations on: the batch's location references flush after the test is gone."""
        self._reimport_with_test_deleted_before_the_location_flush()

    def test_grouped_reimport_reports_its_test_deleted_before_the_finding_groups(self):
        """group_by: finding-group membership is written after every batch, for a test that may be gone."""
        self._import()
        target = self._new_generic_test()
        real_options = self._options

        def grouped_options():
            return {**real_options(), "group_by": "component_name", "create_finding_groups_for_all_findings": True}

        with (
            impersonate(self.user),  # auto-created groups take the current user as creator, as on the API
            patch.object(self, "_options", grouped_options),
            self._delete_target_before(DefaultReImporter, "process_groups_for_all_findings", lambda: target.id),
        ):
            self._assert_reports_deleted_test(lambda: self._reimport(target), "reimport")

    def _async_delete_findings_of(self, test_id):
        """
        What the API's test delete does first (dojo.utils.async_delete_task): delete the test's
        findings in committed chunks, leaving the test row until last.
        """
        deleter = _ConcurrentThread(lambda: bulk_delete_findings(Finding.objects.filter(test_id=test_id)))
        deleter.start()
        deleter.join_or_fail(self)

    def _assert_reports_findings_deleted(self, run, kind):
        """
        A raw foreign-key error is the bug. Failing with the clear message is right; completing is
        acceptable too where every writer it reached already skips rows for findings that are gone.
        """
        try:
            run()
        except IntegrityError as exc:
            self.fail(f"the {kind} surfaced a raw foreign-key error for findings deleted under it: {exc}")
        except ValidationError as exc:
            self.assertIn("deleted while the scan was being processed", str(exc), msg=f"{kind}: {exc}")

    def test_reimport_reports_its_findings_deleted_by_an_in_progress_test_delete(self):
        """The live API shape: the test still exists, its findings are already gone."""
        from dojo.importers.base_location_manager import LocationHandler  # noqa: PLC0415

        self._import()
        target = self._new_generic_test()
        self._reimport(target)
        real_persist = LocationHandler.persist
        fired = threading.Event()

        def delete_the_findings_then_flush(handler, *args, **kwargs):
            if not fired.is_set():
                fired.set()
                self._async_delete_findings_of(target.id)
            return real_persist(handler, *args, **kwargs)

        import dojo.importers.default_reimporter as reimporter_module  # noqa: PLC0415

        real_tags = reimporter_module.bulk_apply_parser_tags

        def delete_the_findings_then_tag(*args, **kwargs):
            if not fired.is_set():
                fired.set()
                self._async_delete_findings_of(target.id)
            return real_tags(*args, **kwargs)

        with (
            patch.object(LocationHandler, "persist", delete_the_findings_then_flush),
            patch.object(reimporter_module, "bulk_apply_parser_tags", delete_the_findings_then_tag),
        ):
            self._assert_reports_findings_deleted(lambda: self._reimport(target), "reimport")
        self.assertTrue(Test.objects.filter(id=target.id).exists(), "the test row is still there, as mid-delete")

    def test_deleting_another_test_that_shares_the_tags_does_not_fail_the_reimport(self):
        other = self._import()  # a different test whose findings carry the same tags
        other_finding_ids = list(Finding.objects.filter(test=other).values_list("id", flat=True))
        target = self._new_generic_test()
        main_pid = _backend_pid()
        deleted = threading.Event()
        commit_now = threading.Event()

        def delete_other_and_hold_until_the_tag_write():
            with transaction.atomic():
                Test.objects.get(id=other.id).delete()
                deleted.set()
                _wait_for(
                    lambda: commit_now.is_set() or _is_waiting_on_a_lock(main_pid),
                    "the reimport's tag write to finish or block on the deleting transaction",
                )

        deleter = _ConcurrentThread(delete_other_and_hold_until_the_tag_write)
        real_tag_write = DefaultReImporter.apply_import_tags_for_batch

        def tag_while_the_other_test_is_being_deleted(importer, *args, **kwargs):
            if not deleted.is_set():
                deleter.start()
                self.assertTrue(deleted.wait(WAIT_TIMEOUT_SECONDS), "the concurrent test delete did not start")
            try:
                return real_tag_write(importer, *args, **kwargs)
            finally:
                commit_now.set()

        with patch.object(DefaultReImporter, "apply_import_tags_for_batch", tag_while_the_other_test_is_being_deleted):
            try:
                self._reimport(target)
            except (IntegrityError, OperationalError) as exc:
                self.fail(f"deleting a different test that shares the tags failed the reimport: {exc!r}")
            finally:
                commit_now.set()
        deleter.join_or_fail(self)

        self.assertFalse(Finding.objects.filter(id__in=other_finding_ids).exists(), "the other test's findings are gone")
        self.assertEqual(Finding.objects.filter(test=target).count(), self.FINDINGS_IN_REPORT)
        tag_model = Finding.tags.tag_model
        through = Finding.tags.through
        for name in self.IMPORT_TAGS:
            tag = tag_model.objects.get(name=name)
            uses = through.objects.filter(**{f"{Finding.tags.field.m2m_reverse_field_name()}": tag}).count()
            self.assertEqual(tag.count, uses, msg=f"tag {name!r}: stored count {tag.count}, actual finding uses {uses}")


# Class-level, so the product's endpoints are still on the legacy model when cleanup deletes them.
@override_settings(V3_FEATURE_LOCATIONS=False)
class TestTaggedImportRacesTestDeleteEndpoints(TestTaggedImportRacesTestDelete):

    """The same races with Locations off, where the batch flush writes Endpoint_Status rows."""

    def test_reimport_reports_its_test_deleted_before_the_endpoint_flush(self):
        """The live 500 (Locations off): the batch's endpoint statuses flush after the test is gone."""
        self._reimport_with_test_deleted_before_the_location_flush()


# Regression: a reimport re-created ("resurrected") a finding deleted while it ran. A report can
# carry several rows that match one finding (one row per CVE for the same package, say); each match
# that changes the finding's CVE saves it. When the finding was deleted between two of those saves
# (a user or client deleting it through the API, or the excess-duplicate delete), Model.save()
# found no row to UPDATE and fell back to an INSERT with the deleted primary key -- re-creating the
# finding without its history, or, with a companion row saved first, failing with "insert or update
# on table ... Key (finding_id)=(N) is not present in table dojo_finding".
@override_settings(IMPORT_REIMPORT_DEDUPE_BATCH_SIZE=1, IMPORT_REIMPORT_MATCH_BATCH_SIZE=1)
class TestReimportRacesMatchedFindingDelete(_DupeDeleteDuringWriteMixin, SimpleTestCase):

    """A finding deleted mid-reimport stays deleted, and the reimport carries on without it."""

    DELETE_DUPLICATES = False  # isolate the API-style delete

    def _report(self):
        # Three rows for one finding: same title, component and location, a different CVE on each.
        return SimpleUploadedFile("report.json", json.dumps({"findings": [
            {
                "title": f"Resurrection race {self.suffix}",
                "severity": "High",
                "description": "Vulnerable package",
                "mitigation": "Upgrade",
                "component_name": "glibc",
                "component_version": "2.31",
                "file_path": "usr/lib/libc.so",
                "vulnerability_ids": [f"CVE-2026-{3000 + i}-{self.suffix.upper()}"],
            }
            for i in range(3)
        ]}).encode(), content_type="application/json")

    def test_finding_deleted_between_two_matches_is_not_resurrected(self):
        target = self._new_generic_test()
        real = DefaultReImporter.finding_post_processing
        matched_calls = []
        deleted = []

        def delete_before_the_second_matched_save(importer, finding, *args, **kwargs):
            if kwargs.get("is_matched_finding"):
                matched_calls.append(finding.pk)
                if len(matched_calls) == 2 and finding.pk:
                    deleted.append(finding.pk)
                    deleter = _ConcurrentThread(lambda: Finding.objects.get(id=finding.pk).delete())
                    deleter.start()
                    deleter.join_or_fail(self)
            return real(importer, finding, *args, **kwargs)

        with patch.object(DefaultReImporter, "finding_post_processing", delete_before_the_second_matched_save):
            try:
                self._reimport(target)
            except Exception as exc:
                self.fail(f"the reimport failed because one matched finding was deleted under it: {exc!r}")

        self.assertEqual(len(deleted), 1, msg=f"setup: the rows must match one finding twice, matched: {matched_calls}")
        self.assertFalse(
            Finding.objects.filter(id=deleted[0]).exists(),
            msg=f"finding {deleted[0]} was deleted mid-reimport and the reimport re-created it",
        )

    def test_mitigated_finding_deleted_before_its_reactivation_is_not_resurrected(self):
        """The reactivation save: a mitigated finding the report brings back, deleted just before."""
        target = self._new_generic_test()
        self._reimport(target)
        finding = Finding.objects.get(test=target)
        Finding.objects.filter(id=finding.id).update(active=False, is_mitigated=True, mitigated=timezone.now())
        real = DefaultReImporter.process_matched_mitigated_finding
        deleted = []

        def delete_then_reactivate(importer, unsaved_finding, existing_finding, *args, **kwargs):
            if not deleted:
                deleted.append(existing_finding.pk)
                deleter = _ConcurrentThread(lambda: Finding.objects.get(id=existing_finding.pk).delete())
                deleter.start()
                deleter.join_or_fail(self)
            return real(importer, unsaved_finding, existing_finding, *args, **kwargs)

        with patch.object(DefaultReImporter, "process_matched_mitigated_finding", delete_then_reactivate):
            try:
                self._reimport(target)
            except Exception as exc:
                self.fail(f"the reimport failed because the finding it was reactivating was deleted: {exc!r}")

        self.assertEqual(deleted, [finding.id], msg="setup: the reimport must reach the reactivation of that finding")
        self.assertFalse(
            Finding.objects.filter(id=finding.id).exists(),
            msg=f"finding {finding.id} was deleted mid-reimport and the reactivation re-created it",
        )


# Regression: POST /api/v2/findings/ returned 500 with "insert or update on table
# dojo_finding_found_by / dojo_finding_cwe / dojo_findingvulnerabilityreference ... Key
# (finding_id)=(N) is not present in table dojo_finding". The create commits the finding and
# deduplicates it inside Finding.save(), then writes found_by, cwe and vulnerability ids; the
# excess-duplicate delete removed the new duplicate in between.
@override_settings(DUPE_DELETE_GRACE_MINUTES=1, DUPE_DELETE_MAX_PER_RUN=1_000_000)
class TestFindingCreateRacesDupeDelete(_DupeDeleteDuringWriteMixin, SimpleTestCase):

    """A finding create must succeed with its M2M rows when dupe-delete fires right after its deduplication."""

    def _post_finding(self, client):
        return client.post("/api/v2/findings/", {
            "test": self.test.id,
            "title": f"Dupe delete during create {self.suffix}",
            "severity": "High",
            "numerical_severity": "S1",
            "description": "Vulnerable component",
            "mitigation": "Upgrade",
            "impact": "x",
            "active": True,
            "verified": False,
            "found_by": [self.test.test_type_id],
            "cwe": 79,
            "vulnerability_ids": [{"vulnerability_id": f"CVE-2026-9999-{self.suffix.upper()}"}],
            "file_path": "src/app.py",
            "line": 7,
        }, format="json", secure=True)

    def test_create_succeeds_when_dupe_delete_fires_after_its_deduplication(self):
        superuser = User.objects.create(username=f"dupe_delete_su_{self.suffix}", is_superuser=True, is_staff=True)
        self.addCleanup(User.objects.filter(id=superuser.id).delete)
        self.addCleanup(lambda: bulk_delete_findings(Finding.objects.filter(test=self.test)))
        client = APIClient()
        client.force_authenticate(user=superuser)

        original = self._post_finding(client)
        self.assertEqual(original.status_code, 201, msg=original.content[:500])
        with self._dupe_delete_fires_after(finding_helper, "do_dedupe_finding_task_internal"):
            duplicate = self._post_finding(client)

        self.assertEqual(
            duplicate.status_code, 201,
            msg=f"create failed (deleted mid-request: {self.deleted_by_dupe_delete}): {duplicate.content[:800]}",
        )
        persisted = Finding.objects.filter(id=duplicate.json()["id"]).first()
        self.assertIsNotNone(persisted, msg="the created duplicate was deleted")
        self.assertTrue(persisted.duplicate, msg="the second create is a duplicate of the first")
        self.assertEqual(
            list(persisted.found_by.values_list("id", flat=True)), [self.test.test_type_id],
            msg="found_by was not persisted",
        )
