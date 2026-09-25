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

import logging
import threading
import time
import uuid
from unittest.mock import patch

from django.db import IntegrityError, OperationalError, connection, connections, transaction
from django.test import SimpleTestCase
from django.utils import timezone

from dojo.finding import deduplication
from dojo.finding import helper as finding_helper
from dojo.finding.deduplication import _flush_duplicate_changes  # noqa: PLC2701
from dojo.finding.helper import bulk_delete_findings
from dojo.models import (
    Alerts,
    Engagement,
    Finding,
    Notifications,
    Product,
    Product_Type,
    Test,
    Test_Type,
    User,
)
from dojo.tags.utils import bulk_add_tags_to_instances

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


class _CommittedFindingsMixin:

    """Create committed findings for one test and remove them afterwards."""

    databases = {"default"}

    def setUp(self):
        super().setUp()
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

    def test_tag_writer_holding_a_tag_row_does_not_fail_the_chunk(self):
        """
        Lock order against the bulk tag writer, which is the one writer that does not follow it.

        bulk_add_tags_to_instances updates a tag's count row before its COMMIT, and only at
        COMMIT does Postgres take FOR KEY SHARE on the finding for the new through row. The
        chunk locks the finding first and then needs that tag row to decrement its count, so
        the two can form a cycle that Postgres breaks with a deadlock error. The chunk is the
        side that started waiting first, so it is the one aborted, and its conflict retry
        re-runs it after the writer committed: the chunk still deletes, the writer's through
        row goes with it, and the tag count stays consistent.
        """
        tagged_by_writer, already_tagged = self._create_findings("Race tag writer target", "Race tag writer peer")
        tag_name = f"race-{self.suffix}"
        already_tagged.tags.add(tag_name)
        tag_model = Finding.tags.tag_model
        main_pid = _backend_pid()
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

        writer = _ConcurrentThread(tag_then_commit_once_the_chunk_waits)
        writer.start()
        self.assertTrue(writer_holds_tag_row.wait(WAIT_TIMEOUT_SECONDS), "the concurrent tag writer did not start")
        chunk_started.set()
        with patch.object(finding_helper, "BULK_DELETE_RETRY_DELAY", 0.01):
            bulk_delete_findings(Finding.objects.filter(id__in=[tagged_by_writer.id, already_tagged.id]))
        writer.join_or_fail(self)

        self.assertFalse(Finding.objects.filter(id__in=[tagged_by_writer.id, already_tagged.id]).exists())
        self.assertFalse(
            Finding.tags.through.objects.filter(finding_id__in=[tagged_by_writer.id, already_tagged.id]).exists(),
            "no tag through row may survive for the deleted findings",
        )
        self.assertEqual(tag_model.objects.get(name=tag_name).count, 0, "both tag uses were decremented")
        tag_model.objects.filter(name=tag_name).delete()
