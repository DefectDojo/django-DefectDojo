"""
Migration 0305 can be re-run after a partial failure.

0305 builds its indexes with CREATE INDEX CONCURRENTLY in a non-atomic migration. A build
that is interrupted leaves its index in the catalog marked INVALID, and a plain
AddIndexConcurrently then fails every retry with "relation ... already exists". These tests
run one of its operations (the index on dojo_test) against the real catalog states a retry
can meet: an INVALID leftover, a valid index from an earlier run, no index, and a build that
is still running on the server after the process that started it was killed.

CREATE INDEX CONCURRENTLY cannot run inside a transaction, so these are SimpleTestCase tests
on autocommit connections (a TestCase wraps each test in one), and they put the index back
afterwards.
"""

import importlib
import threading
import time
from unittest.mock import Mock, patch

import psycopg
from django.db import IntegrityError, connection
from django.db.migrations.loader import MigrationLoader
from django.test import SimpleTestCase

NAME = ("dojo", "0305_archive_batch_indexes")
INDEX = "dojo_test_archive_batch"
SCRATCH_TABLE = "unittest_0305_scratch"
WAIT_TIMEOUT_SECONDS = 30
BUILDER_APPLICATION_NAME = "unittest_0305_builder"
HOLD_LOCK_KEY = 305_0305
HOLD_FUNCTION = "unittest_0305_hold_build"


def _index():
    """Return (oid, indisvalid, table) for the index, or None when it does not exist."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT i.indexrelid::bigint, i.indisvalid, i.indrelid::regclass::text"
            " FROM pg_index i WHERE i.indexrelid = to_regclass(%s)",
            [INDEX],
        )
        return cursor.fetchone()


def _execute(sql):
    with connection.cursor() as cursor:
        cursor.execute(sql)


class TestMigration0305Rerun(SimpleTestCase):

    databases = {"default"}

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        migration = importlib.import_module(f"dojo.db_migrations.{NAME[1]}").Migration
        cls.operation = next(op for op in migration.operations if op.index.name == INDEX)
        cls.state = MigrationLoader(connection).project_state(NAME)

    def setUp(self):
        super().setUp()
        self.addCleanup(self._restore)

    def _restore(self):
        _execute(f"DROP TABLE IF EXISTS {SCRATCH_TABLE}")
        self._run_operation()

    def _run_operation(self):
        with connection.schema_editor(atomic=False) as editor:
            self.operation.database_forwards("dojo", editor, self.state, self.state)

    def _leave_invalid_index(self):
        """Leave an INVALID index named INDEX, as an interrupted build does, without superuser rights."""
        _execute(f"DROP INDEX IF EXISTS {INDEX}")
        _execute(f"CREATE TABLE {SCRATCH_TABLE} (v integer)")
        _execute(f"INSERT INTO {SCRATCH_TABLE} VALUES (1), (1)")
        with self.assertRaises(IntegrityError):
            _execute(f"CREATE UNIQUE INDEX CONCURRENTLY {INDEX} ON {SCRATCH_TABLE} (v)")
        self.assertFalse(_index()[1], "the failed build should leave an INVALID index")

    def test_invalid_leftover_is_dropped_and_rebuilt(self):
        self._leave_invalid_index()
        leftover_oid = _index()[0]

        self._run_operation()

        oid, valid, table = _index()
        self.assertTrue(valid)
        self.assertEqual("dojo_test", table)
        self.assertNotEqual(leftover_oid, oid)

    def test_valid_index_is_kept(self):
        oid_before = _index()[0]

        self._run_operation()

        self.assertEqual((oid_before, True, "dojo_test"), _index())

    def test_missing_index_is_built(self):
        _execute(f"DROP INDEX {INDEX}")

        self._run_operation()

        self.assertEqual((True, "dojo_test"), _index()[1:])

    def test_build_still_running_is_waited_for_and_kept(self):
        """
        A build left running on the server by a killed process is waited for, not dropped.

        The build is held in progress by another transaction's open snapshot, which a
        concurrent index build has to wait out, and the snapshot is released while the
        operation is polling.
        """
        _execute(f"DROP INDEX {INDEX}")
        params = connection.get_connection_params()
        build_error = []

        with psycopg.connect(**params) as snapshot_holder:
            snapshot_holder.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            snapshot_holder.execute("SELECT 1")

            def build():
                try:
                    with psycopg.connect(**params, autocommit=True) as builder:
                        builder.execute(
                            f"CREATE INDEX CONCURRENTLY {INDEX} ON dojo_test (archive_batch)"
                            " WHERE archive_batch IS NOT NULL",
                        )
                except Exception as error:  # reported by the assertion on build_error below
                    build_error.append(error)

            builder_thread = threading.Thread(target=build)
            builder_thread.start()
            with connection.cursor() as cursor:
                deadline = time.monotonic() + WAIT_TIMEOUT_SECONDS
                while not self.operation._build_in_progress(cursor, INDEX):
                    self.assertLess(time.monotonic(), deadline, "the concurrent build never started")
                    time.sleep(0.05)
            in_flight_oid, valid, _ = _index()
            self.assertFalse(valid, "the build should still be running")

            # The snapshot is released from inside the wait, not on a timer: a timer that fires
            # before the operation first looks lets the build finish unseen on a slow runner.
            # The second check is the wait loop's first, so the wait has started by then. The
            # build is let finish and its transaction end before that check answers (still in
            # progress, as it was when the check began), so the next one sees it done.
            real_build_in_progress = self.operation._build_in_progress
            checks = []

            def build_in_progress(cursor, quoted_name):
                checks.append(quoted_name)
                if len(checks) == 2:
                    snapshot_holder.commit()
                    builder_thread.join(WAIT_TIMEOUT_SECONDS)
                    return True
                return real_build_in_progress(cursor, quoted_name)

            with (
                patch.object(self.operation, "poll_seconds", 0.1),
                patch.object(self.operation, "_build_in_progress", build_in_progress),
                self.assertLogs(f"dojo.db_migrations.{NAME[1]}", "WARNING") as logs,
            ):
                self._run_operation()
            self.assertGreaterEqual(len(checks), 2)
            # Once when the wait starts and once when it ends, however many polls it took.
            self.assertEqual(2, len(logs.records))

        builder_thread.join(WAIT_TIMEOUT_SECONDS)
        self.assertEqual([], build_error)
        self.assertEqual((in_flight_oid, True, "dojo_test"), _index())

    def test_build_ending_is_waited_for_until_it_commits(self):
        """
        A build whose progress row has ended but whose transaction has not committed is kept.

        Postgres ends a concurrent build's pg_stat_progress_create_index row a moment before the
        build's last transaction commits, and until then indisvalid still reads false. A
        ddl_command_end event trigger runs in that window, so one that waits on an advisory lock
        holds the real build there for as long as the test needs, with no timing involved.
        """
        with connection.cursor() as cursor:
            cursor.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
            if not cursor.fetchone()[0]:
                self.skipTest("needs a superuser to create an event trigger")
        _execute(f"DROP INDEX {INDEX}")
        params = connection.get_connection_params()
        build_error = []

        lock_holder = psycopg.connect(**params, autocommit=True)
        self.addCleanup(lock_holder.close)  # also releases the lock if the test fails early
        lock_holder.execute("SELECT pg_advisory_lock(%s)", [HOLD_LOCK_KEY])
        # A run killed before its cleanups leaves both in a kept test database: clear them first.
        _execute(f"DROP EVENT TRIGGER IF EXISTS {HOLD_FUNCTION}")
        _execute(
            f"CREATE OR REPLACE FUNCTION {HOLD_FUNCTION}() RETURNS event_trigger LANGUAGE plpgsql AS $$"
            f" BEGIN IF current_setting('application_name') = '{BUILDER_APPLICATION_NAME}' THEN"
            f" PERFORM pg_advisory_xact_lock({HOLD_LOCK_KEY}); END IF; END $$",
        )
        self.addCleanup(_execute, f"DROP FUNCTION {HOLD_FUNCTION}()")
        _execute(
            f"CREATE EVENT TRIGGER {HOLD_FUNCTION} ON ddl_command_end"
            f" WHEN TAG IN ('CREATE INDEX') EXECUTE FUNCTION {HOLD_FUNCTION}()",
        )
        self.addCleanup(_execute, f"DROP EVENT TRIGGER {HOLD_FUNCTION}")

        def build():
            try:
                with psycopg.connect(**params, autocommit=True, application_name=BUILDER_APPLICATION_NAME) as builder:
                    builder.execute(
                        f"CREATE INDEX CONCURRENTLY {INDEX} ON dojo_test (archive_batch)"
                        " WHERE archive_batch IS NOT NULL",
                    )
            except Exception as error:  # reported by the assertion on build_error below
                build_error.append(error)

        builder_thread = threading.Thread(target=build)
        builder_thread.start()
        self.addCleanup(builder_thread.join, WAIT_TIMEOUT_SECONDS)
        self.addCleanup(lock_holder.execute, "SELECT pg_advisory_unlock_all()")
        with connection.cursor() as cursor:
            deadline = time.monotonic() + WAIT_TIMEOUT_SECONDS
            while True:
                cursor.execute(
                    "SELECT 1 FROM pg_stat_activity WHERE application_name = %s"
                    " AND wait_event_type = 'Lock' AND wait_event = 'advisory'",
                    [BUILDER_APPLICATION_NAME],
                )
                if cursor.fetchone() is not None:
                    break
                self.assertLess(time.monotonic(), deadline, "the build never reached its event trigger")
                self.assertTrue(builder_thread.is_alive(), build_error)
                time.sleep(0.05)
            # The state the migration meets in that window: no progress row, and not valid yet.
            cursor.execute(
                "SELECT 1 FROM pg_stat_progress_create_index WHERE index_relid = to_regclass(%s)", [INDEX],
            )
            self.assertIsNone(cursor.fetchone(), "the build's progress row should have ended")
        in_flight_oid, valid, _ = _index()
        self.assertFalse(valid, "the build's commit should still be held back")

        # The build is let commit from inside the wait, the first time the operation sleeps.
        migration_module = importlib.import_module(f"dojo.db_migrations.{NAME[1]}")
        sleeps = []

        def sleep(seconds):
            sleeps.append(seconds)
            if len(sleeps) == 1:
                lock_holder.execute("SELECT pg_advisory_unlock(%s)", [HOLD_LOCK_KEY])
                builder_thread.join(WAIT_TIMEOUT_SECONDS)

        dropped = []

        with connection.schema_editor(atomic=False) as editor:
            real_execute = editor.execute

            def execute(sql, params=()):
                if str(sql).startswith("DROP INDEX"):
                    # Refused rather than run: the drop would wait on the held build and hang.
                    dropped.append(str(sql))
                    msg = f"dropped an index whose build had not committed yet: {sql}"
                    raise AssertionError(msg)
                return real_execute(sql, params)

            with (
                patch.object(editor, "execute", execute),
                patch.object(migration_module, "time", Mock(sleep=sleep)),
                self.assertLogs(f"dojo.db_migrations.{NAME[1]}", "WARNING") as logs,
            ):
                self.operation.database_forwards("dojo", editor, self.state, self.state)

        self.assertEqual([], dropped)
        self.assertEqual(1, len(sleeps))
        self.assertEqual(2, len(logs.records))
        builder_thread.join(WAIT_TIMEOUT_SECONDS)
        self.assertEqual([], build_error)
        self.assertEqual((in_flight_oid, True, "dojo_test"), _index())

    def test_build_ending_runs_over_what_a_killed_run_left_behind(self):
        """
        A run killed before its cleanups leaves the event trigger and its function in a kept test
        database (a CI timeout, an OOM kill, Ctrl-C). The next --keepdb run must not trip over them.
        """
        with connection.cursor() as cursor:
            cursor.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
            if not cursor.fetchone()[0]:
                self.skipTest("needs a superuser to create an event trigger")
        # Registered first, so it runs last and clears both even when the test below fails.
        self.addCleanup(_execute, f"DROP FUNCTION IF EXISTS {HOLD_FUNCTION}()")
        self.addCleanup(_execute, f"DROP EVENT TRIGGER IF EXISTS {HOLD_FUNCTION}")
        _execute(f"CREATE FUNCTION {HOLD_FUNCTION}() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN END $$")
        _execute(
            f"CREATE EVENT TRIGGER {HOLD_FUNCTION} ON ddl_command_end"
            f" WHEN TAG IN ('CREATE INDEX') EXECUTE FUNCTION {HOLD_FUNCTION}()",
        )

        self.test_build_ending_is_waited_for_until_it_commits()
