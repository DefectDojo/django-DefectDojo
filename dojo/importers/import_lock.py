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

A second lock, on its own key, keeps two imports out of one test at the same time. Two imports
or reimports into one test match and write the same finding rows, and running together they
deadlock (SQLSTATE 40P01) or have their statements cancelled (57014); a client that times out on a
long reimport and retries it starts exactly that. So an import takes this lock exclusively before
its first finding is matched or created, and holds it until it ends. An import that finds it
taken waits its turn, for up to DD_SERIALIZE_TEST_IMPORTS_WAIT_SECONDS, then runs as it would have; only
a wait that runs out fails, with TestImportInProgress (HTTP 409). It is a separate key because
the first one is shared by design: an import's deduplication batches take it while that import
waits for them (deduplication mode "async_wait"), and the delete must keep seeing every one of
them. The same caveats hold: DD_SERIALIZE_TEST_IMPORTS=False turns it off behind a pooler in
transaction mode, and a holder idle for DUPE_DELETE_ABANDONED_IMPORT_LOCK_MINUTES no longer
holds an import back.
"""
import logging
import time

from django.conf import settings
from django.db import DatabaseError, connection
from django.utils.translation import gettext as _
from rest_framework.exceptions import APIException
from rest_framework.status import HTTP_409_CONFLICT

from dojo.models import Finding, System_Settings

logger = logging.getLogger(__name__)

# First key of the two-key pg_advisory_lock form; the second is the test id. Any constant works as
# long as nothing else in the application locks on it.
TEST_IMPORT_LOCK_CLASS = 0x44440001
# First key of the lock that lets one import at a time into a test; the second is the test id.
TEST_IMPORT_TURN_LOCK_CLASS = 0x44440002
# How often an import waiting for its turn on a test asks again.
TEST_IMPORT_TURN_POLL_SECONDS = 1.0


class TestImportInProgress(APIException):

    """Another import into the test did not finish within DD_SERIALIZE_TEST_IMPORTS_WAIT_SECONDS."""

    status_code = HTTP_409_CONFLICT
    default_code = "test_import_in_progress"


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


def _import_lock_holders(test_ids=None, lock_class=TEST_IMPORT_LOCK_CLASS):
    """
    (test id, backend pid, backend state, seconds since its state changed) for each holder of an import lock.

    The state and its age are NULL for a backend this database user may not see, such as one of
    another role.

    pg_locks lists the advisory locks of every database on the server, but an advisory lock only
    conflicts within its own database, so only this database's holders count. Another DefectDojo
    database on the same server (or another parallel test worker's) has its own test with this id.
    """
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT locks.objid::bigint, locks.pid, activity.state,
                   EXTRACT(EPOCH FROM clock_timestamp() - activity.state_change)
            FROM pg_locks AS locks
            LEFT JOIN pg_stat_activity AS activity ON activity.pid = locks.pid
            WHERE locks.locktype = 'advisory' AND locks.granted AND locks.objsubid = 2
              AND locks.database = (SELECT oid FROM pg_database WHERE datname = current_database())
              AND locks.classid::bigint = %s AND (%s::bigint[] IS NULL OR locks.objid::bigint = ANY(%s::bigint[]))
            """,
            [lock_class, test_ids, test_ids],
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


def wait_for_test_import_turn(test_id, wait_seconds=None, on_taken=None):
    """
    Take the lock that lets one import at a time into the test, waiting for an import holding it to end.

    ``wait_seconds`` overrides DD_SERIALIZE_TEST_IMPORTS_WAIT_SECONDS for a caller that must not block: 0 only
    tries, which is what a background import in a worker does before it queues itself again.

    ``on_taken(test_id)`` runs as soon as the lock is taken, before this returns, so the caller records it for
    release in the same guarded step. Anything that interrupts the take before it is recorded (a time limit, a
    broken connection, ``on_taken`` itself) gives the lock back, so nothing is left holding a test that no
    import will release.

    Returns True when this connection holds the lock (release it with release_test_import_turns),
    False when it was not taken: the lock is turned off, or the import holding it has been idle
    long enough to count as abandoned (see abandoned_tests), so this import goes ahead the way every
    import did before the lock existed. Raises TestImportInProgress when the other import has not
    finished within the wait.

    The lock is per connection and counted, so an import nested in another on the same connection
    (a background import run in-process) gets it at once. It is polled with a try-lock rather than
    waited for in PostgreSQL: a blocking wait would be cancelled by a statement timeout, and it
    leaves the transaction usable whatever happens to the wait.
    """
    if not settings.SERIALIZE_TEST_IMPORTS:
        return False
    wait_seconds = max(settings.SERIALIZE_TEST_IMPORTS_WAIT_SECONDS if wait_seconds is None else wait_seconds, 0)
    deadline = time.monotonic() + wait_seconds
    waited = False
    with connection.cursor() as cursor:
        while True:
            if _try_test_import_turn(cursor, test_id, on_taken):
                if waited:
                    logger.info("test %s: the other import has finished, this one starts now", test_id)
                return True
            holders = _import_lock_holders([test_id], TEST_IMPORT_TURN_LOCK_CLASS)
            if test_id in abandoned_tests(holders, _abandoned_threshold_seconds()):
                logger.warning(
                    "importing into test %s without waiting for the import lock that is held on it: every connection "
                    "holding it has been idle for over %s minutes, so no import is running (holding backends: %s)",
                    test_id, settings.DUPE_DELETE_ABANDONED_IMPORT_LOCK_MINUTES, sorted({holder[1] for holder in holders}),
                )
                return False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                logger.warning(
                    "test %s: gave up after waiting %s seconds for another import into it to finish",
                    test_id, wait_seconds,
                )
                raise TestImportInProgress(test_import_in_progress_message(test_id, wait_seconds))
            if not waited:
                logger.info("test %s: another import into it is running, waiting for it to finish", test_id)
                waited = True
            time.sleep(min(TEST_IMPORT_TURN_POLL_SECONDS, remaining))


def _try_test_import_turn(cursor, test_id, on_taken):
    """One try for the test's turn; a take that is interrupted before ``on_taken`` has recorded it is given back."""
    recorded = False
    try:
        cursor.execute("SELECT pg_try_advisory_lock(%s, %s)", [TEST_IMPORT_TURN_LOCK_CLASS, test_id])
        if not cursor.fetchone()[0]:
            return False
        if on_taken is not None:
            on_taken(test_id)
        recorded = True
    except BaseException:
        if not recorded:
            _give_back_test_import_turn(test_id)
        raise
    return True


def _give_back_test_import_turn(test_id):
    """
    Release a turn that may or may not have been taken, without a word if it was not.

    pg_advisory_unlock on a lock this session does not hold only returns false. If the release itself fails (an
    aborted transaction, a broken connection), the connection is marked to be closed at the end of the request
    or task, which releases the lock with it, as release_test_import_turns does.
    """
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_unlock(%s, %s)", [TEST_IMPORT_TURN_LOCK_CLASS, test_id])
    except BaseException as exc:
        connection.close_at = time.monotonic()
        if not isinstance(exc, DatabaseError):
            raise


def test_import_in_progress_message(test_id, wait_seconds):
    return _(
        "Another import or reimport into test %(test_id)s is still running. This one waited %(seconds)s seconds for it "
        "to finish and then gave up, so nothing was imported. Run it again once the other import has finished.",
    ) % {"test_id": test_id, "seconds": wait_seconds}


def release_test_import_turns(test_ids):
    """
    Release locks taken by wait_for_test_import_turn.

    If the release fails, the connection is marked to be closed at the end of the request or task,
    which releases the lock with it, as unlock_tests_under_import does.
    """
    if not test_ids:
        return
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT test_id, pg_advisory_unlock(%s, test_id) FROM unnest(%s::int[]) AS test_id",
                [TEST_IMPORT_TURN_LOCK_CLASS, list(test_ids)],
            )
            not_held = [test_id for test_id, released in cursor.fetchall() if not released]
    except BaseException as exc:
        connection.close_at = time.monotonic()
        logger.warning(
            "could not release the lock that lets one import at a time into tests %s; closing the connection at the "
            "end of this request or task releases it",
            test_ids,
        )
        if not isinstance(exc, DatabaseError):
            raise
        return
    if not_held:
        logger.error(
            "the lock that lets one import at a time into tests %s was not held by this connection when the import "
            "released it. DefectDojo is probably connected to PostgreSQL through a pooler in transaction mode, where the "
            "lock cannot work and is left behind; set DD_SERIALIZE_TEST_IMPORTS=False",
            not_held,
        )
