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
from unittest.mock import patch

import psycopg
from django.db import IntegrityError, connection
from django.db.migrations.loader import MigrationLoader
from django.test import SimpleTestCase

NAME = ("dojo", "0305_archive_batch_indexes")
INDEX = "dojo_test_archive_batch"
SCRATCH_TABLE = "unittest_0305_scratch"
WAIT_TIMEOUT_SECONDS = 30


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

            release = threading.Timer(1, snapshot_holder.commit)
            release.start()
            with (
                patch.object(self.operation, "poll_seconds", 0.1),
                self.assertLogs(f"dojo.db_migrations.{NAME[1]}", "WARNING") as logs,
            ):
                self._run_operation()
            release.join()
            # Once when the wait starts and once when it ends, however many polls it took.
            self.assertEqual(2, len(logs.records))

        builder_thread.join(WAIT_TIMEOUT_SECONDS)
        self.assertEqual([], build_error)
        self.assertEqual((in_flight_oid, True, "dojo_test"), _index())
