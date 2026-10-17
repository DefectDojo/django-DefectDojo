"""
A lock that says "an import is writing this test's findings right now".

The excess-duplicate delete (dojo.tasks.async_dupe_delete) must not remove a duplicate that an
import created or matched and is still writing. The child rows the import writes next (found_by,
tags, vulnerability ids, location statuses, finding groups, companions) reference the finding
through foreign keys Django declares DEFERRABLE INITIALLY DEFERRED, so the import holds no lock
on the finding that a delete would wait for: it only fails at its COMMIT, and loses the run.

So an import holds a shared PostgreSQL advisory lock keyed on its test for as long as it runs,
and each deduplication batch holds one while it works. The delete takes the same key exclusively
with a try-lock, one transaction per chunk: a test whose lock is held is skipped for this run,
and every other test is cleaned up exactly as before. The lock is gone the moment the import
finishes, and a worker that dies takes its lock with its connection, so nothing can hold a test
back after the import that needed it has ended.

A lock must never outlive its import, or that test's duplicates would never be deleted again. So:

- A release that fails (the import's transaction aborted, the connection broke) marks the
  connection to be closed, and Django closes it when the request or task ends, which drops the
  lock, however long the connection would otherwise have been kept.
- Session-level advisory locks need the import's statements to run on one server connection, which
  holds for Django's direct connections and for a pooler in session mode. Behind a pooler in
  transaction mode the release can land on another server connection and find nothing; that is
  logged as an error naming DD_DUPE_DELETE_SKIP_TESTS_UNDER_IMPORT=False, which turns the lock off.
- The delete treats a lock as abandoned once every connection holding it has sat idle for
  DUPE_DELETE_ABANDONED_IMPORT_LOCK_MINUTES. An import issues statements continuously, so only a
  lock left behind (a host that died without closing its connection, a pooler) looks like that.
"""
import logging
import time

from django.conf import settings
from django.db import DatabaseError, connection

from dojo.models import Finding, System_Settings

logger = logging.getLogger(__name__)

# First key of the two-key pg_advisory_lock form; the second is the test id. Any constant works as
# long as nothing else in the application locks on it.
TEST_IMPORT_LOCK_CLASS = 0x44440001


def import_lock_enabled():
    """Only duplicate deletion reads the lock, so an instance without it takes none."""
    if not settings.DUPE_DELETE_SKIP_TESTS_UNDER_IMPORT:
        return False
    return System_Settings.objects.get().delete_duplicates


def lock_tests_under_import(test_ids):
    """
    Take the shared import lock on each test, waiting for a delete chunk working on it to commit.

    Returns the ids locked, to hand to unlock_tests_under_import. The lock is per connection
    and counted, so taking it again for a test this connection already holds is harmless as long
    as every lock is released once.
    """
    ids = sorted({int(test_id) for test_id in test_ids if test_id is not None})
    if not ids or not import_lock_enabled():
        return []
    # One at a time, so a wait that is cancelled part way (a statement timeout, a time limit) leaves
    # behind none of the locks it had already taken.
    locked = []
    try:
        with connection.cursor() as cursor:
            for test_id in ids:
                cursor.execute("SELECT pg_advisory_lock_shared(%s, %s)", [TEST_IMPORT_LOCK_CLASS, test_id])
                locked.append(test_id)
    except BaseException:
        unlock_tests_under_import(locked)
        raise
    return locked


def lock_tests_of_findings_under_import(finding_ids):
    """lock_tests_under_import for the tests these findings belong to, before any is loaded."""
    if not finding_ids or not import_lock_enabled():
        return []
    return lock_tests_under_import(
        Finding.objects.filter(id__in=finding_ids).order_by().values_list("test_id", flat=True).distinct(),
    )


def unlock_tests_under_import(test_ids):
    """
    Release locks taken by lock_tests_under_import.

    If the release fails, the connection is marked to be closed at the end of the request or task,
    which releases the lock with it.
    """
    if not test_ids:
        return
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT test_id, pg_advisory_unlock_shared(%s, test_id) FROM unnest(%s::int[]) AS test_id",
                [TEST_IMPORT_LOCK_CLASS, list(test_ids)],
            )
            not_held = [test_id for test_id, released in cursor.fetchall() if not released]
    except BaseException as exc:
        # Whatever stopped the release (an aborted transaction, a broken connection, a time limit),
        # the lock goes with the connection, so make sure Django closes it.
        connection.close_at = time.monotonic()
        logger.warning(
            "could not release the import lock on tests %s; closing the connection at the end of this request or task "
            "releases it",
            test_ids,
        )
        if not isinstance(exc, DatabaseError):
            raise
        return
    if not_held:
        logger.error(
            "the import lock on tests %s was not held by this connection when the import released it. DefectDojo is "
            "probably connected to PostgreSQL through a pooler in transaction mode, where the lock cannot work and is "
            "left behind; set DD_DUPE_DELETE_SKIP_TESTS_UNDER_IMPORT=False",
            not_held,
        )


def tests_with_import_lock_held():
    """
    Every test an import is running on right now, for the delete's selection.

    Read without taking any lock, so it can be stale by the time a chunk runs; the chunk checks
    again under the lock (tests_under_import_now). Its job is only to keep tests under import from
    using up the run's cap, so that the run reaches every other test.
    """
    if not settings.DUPE_DELETE_SKIP_TESTS_UNDER_IMPORT:
        return set()
    holders = _import_lock_holders()
    return {test_id for test_id, *_ in holders} - abandoned_tests(holders, _abandoned_threshold_seconds())


def tests_under_import_now(test_ids):
    """
    For the delete, inside its chunk transaction: which of these tests an import is writing.

    Takes the lock exclusively, until the transaction ends, on every test that is free, so an
    import starting on one of them waits for the chunk to commit; it then finds those duplicates
    gone rather than half deleted. Never waits itself.
    """
    ids = sorted({int(test_id) for test_id in test_ids})
    if not ids or not settings.DUPE_DELETE_SKIP_TESTS_UNDER_IMPORT:
        return set()
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT test_id FROM unnest(%s::int[]) AS test_id WHERE NOT pg_try_advisory_xact_lock(%s, test_id)",
            [ids, TEST_IMPORT_LOCK_CLASS],
        )
        busy = {row[0] for row in cursor.fetchall()}
    return busy - _abandoned(busy)


def _abandoned_threshold_seconds():
    return settings.DUPE_DELETE_ABANDONED_IMPORT_LOCK_MINUTES * 60


def _import_lock_holders(test_ids=None):
    """
    (test id, backend pid, backend state, seconds since its state changed) for each import-lock holder.

    The state and its age are NULL for a backend this database user may not see, such as one of
    another role.
    """
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT locks.objid::bigint, locks.pid, activity.state,
                   EXTRACT(EPOCH FROM clock_timestamp() - activity.state_change)
            FROM pg_locks AS locks
            LEFT JOIN pg_stat_activity AS activity ON activity.pid = locks.pid
            WHERE locks.locktype = 'advisory' AND locks.granted AND locks.objsubid = 2
              AND locks.classid::bigint = %s AND (%s::bigint[] IS NULL OR locks.objid::bigint = ANY(%s::bigint[]))
            """,
            [TEST_IMPORT_LOCK_CLASS, test_ids, test_ids],
        )
        return cursor.fetchall()


def abandoned_tests(holders, threshold_seconds):
    """
    The tests whose every lock holder has been idle for longer than ``threshold_seconds``.

    ``holders`` are rows from _import_lock_holders. A holder whose state is not visible counts as a
    live import, so this only ever gives a test back to the delete, never takes one away from an
    import. A threshold of 0 or less turns it off.
    """
    if threshold_seconds <= 0:
        return set()
    live, idle = set(), set()
    for test_id, _pid, state, idle_seconds in holders:
        if state == "idle" and idle_seconds is not None and idle_seconds > threshold_seconds:
            idle.add(test_id)
        else:
            live.add(test_id)
    return idle - live


def _abandoned(test_ids):
    """Of these locked tests, those whose lock has been left behind (see abandoned_tests)."""
    threshold = _abandoned_threshold_seconds()
    if not test_ids or threshold <= 0:
        return set()
    holders = _import_lock_holders(sorted(test_ids))
    abandoned = abandoned_tests(holders, threshold)
    if abandoned:
        logger.warning(
            "deleting excess duplicates of tests %s despite their import lock: every connection holding it has been "
            "idle for over %s minutes, so no import is running (holding backends: %s)",
            sorted(abandoned), settings.DUPE_DELETE_ABANDONED_IMPORT_LOCK_MINUTES,
            sorted({pid for test_id, pid, *_ in holders if test_id in abandoned}),
        )
    return abandoned
