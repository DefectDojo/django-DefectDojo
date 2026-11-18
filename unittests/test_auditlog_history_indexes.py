"""
An object's history is read from the pghistory event tables through indexes, not full scans.

``DojoEvents.objects.references(obj)`` reads every event table with a foreign key to ``obj``'s model,
filtering each on that key, and pghistory's copies of the keys carry no index of their own. Each
event's diff is then computed from the object's previous event, looked up by ``pgh_obj_id`` and
``pgh_id``. Without indexes for both, one finding's history read every row of the Finding event
table, and every event of the finding once per event shown: minutes on a large instance.
"""
import importlib
import threading
import time
from unittest import mock

import psycopg
from django.apps import apps
from django.db import connection, migrations, models
from django.db.migrations.loader import MigrationLoader
from django.db.migrations.state import ProjectState
from django.test import SimpleTestCase
from pghistory import core, utils

from unittests.dojo_test_case import DojoTestCase


def _tracked_dojo_models():
    """The open source models with event tables, other than many-to-many through tables and users."""
    tracked = set()
    for event_model in core.event_models():
        model = event_model.pgh_tracked_model._meta.concrete_model
        if model._meta.app_label == "dojo" and not model._meta.auto_created and model._meta.model_name != "dojo_user":
            tracked.add(model)
    return tracked


def _valid_indexes():
    """(table, first column, second column or None) for every valid index on an event table."""
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT c.relname, a0.attname, a1.attname
            FROM pg_index i
            JOIN pg_class c ON c.oid = i.indrelid
            JOIN pg_attribute a0 ON a0.attrelid = i.indrelid AND a0.attnum = i.indkey[0]
            LEFT JOIN pg_attribute a1 ON a1.attrelid = i.indrelid AND a1.attnum = i.indkey[1]
            WHERE i.indisvalid AND c.relname LIKE %s
            """,
            ["%event"],
        )
        return set(cursor.fetchall())


class HistoryLookupIndexesTest(DojoTestCase):

    def test_every_column_a_history_read_filters_on_leads_an_index(self):
        leading = {(table, first) for table, first, _second in _valid_indexes()}
        read = {
            (event_model._meta.db_table, field.column)
            for model in _tracked_dojo_models()
            for event_model in core.event_models(references_model=model)
            if event_model._meta.app_label == "dojo"
            for field in event_model._meta.fields
            if utils.related_model(field) == model
        }
        self.assertIn(("dojo_findingevent", "duplicate_finding_id"), read)
        self.assertEqual(set(), read - leading)

    def test_every_tracked_models_event_table_has_a_previous_event_index(self):
        composite = {table for table, first, second in _valid_indexes() if (first, second) == ("pgh_obj_id", "pgh_id")}
        tables = {event_model._meta.db_table for model in _tracked_dojo_models() for event_model in core.event_models(tracks_model=model)}
        self.assertIn("dojo_findingevent", tables)
        self.assertEqual(set(), tables - composite)

    def test_a_nullable_key_gets_a_partial_index(self):
        finding_event = apps.get_model("dojo", "FindingEvent")
        conditions = {index.name: index.condition for index in finding_event._meta.indexes}
        self.assertIsNone(conditions["dojo_findingevt_test_hist"])
        self.assertEqual("(AND: ('duplicate_finding__isnull', False))", str(conditions["dojo_findingevt_dupe_hist"]))


class HistoryLookupIndexMigrationTest(DojoTestCase):

    """
    ``dojo.0307`` updates the migration state once for all its indexes, and nothing in it waits without a bound.

    Adding an index to a rendered migration state re-renders the model and every model related to it.
    One operation per index did that for every index each time the migration was applied or
    unapplied, and a run that rewinds and reapplies migrations paid it on every pass.
    """

    migration_key = ("dojo", "0307_event_history_lookup_indexes")

    def test_it_re_renders_the_migration_state_once_for_all_its_indexes(self):
        loader = MigrationLoader(connection=None, ignore_no_migrations=True)
        migration = loader.graph.nodes[self.migration_key]
        state = loader.project_state(self.migration_key, at_end=False)
        # Rendered, as it is while migrate applies and unapplies migrations.
        state.apps  # noqa: B018
        reload = ProjectState._reload

        with mock.patch.object(ProjectState, "_reload", autospec=True, side_effect=reload) as reloads:
            migration.mutate_state(state, preserve=False)

        self.assertEqual(1, len(migration.operations))
        self.assertGreater(len(migration.operations[0].indexes), 30)
        self.assertEqual(1, reloads.call_count)

    def test_its_migration_state_is_what_an_add_index_per_index_gives(self):
        loader = MigrationLoader(connection=None, ignore_no_migrations=True)
        operation = loader.graph.nodes[self.migration_key].operations[0]
        before = loader.project_state(self.migration_key, at_end=False)
        batched, one_by_one = before.clone(), before.clone()

        operation.state_forwards("dojo", batched)
        for model_name, index in operation.indexes:
            migrations.AddIndex(model_name, index).state_forwards("dojo", one_by_one)

        # Options, where the indexes live: two plain clones of one state already compare unequal as whole ModelStates.
        self.assertEqual(
            {key: model.options for key, model in one_by_one.models.items()},
            {key: model.options for key, model in batched.models.items()},
        )

    def test_waiting_for_another_sessions_build_of_the_index_gives_up_at_its_bound(self):
        operation_class = importlib.import_module(f"dojo.db_migrations.{self.migration_key[1]}").AddHistoryLookupIndexes
        operation = operation_class(indexes=[])
        operation.concurrent_build_wait_seconds = 0
        operation.poll_seconds = 0

        with (
            mock.patch.object(operation_class, "_build_in_progress", return_value=True),
            self.assertRaisesRegex(RuntimeError, "run the migration again once it ends"),
        ):
            operation._wait_for_other_build(cursor=None, index_name="dojo_example_hist")


def _session_settings():
    """The settings a concurrent index build changes for its own session."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT current_setting('lock_timeout'), current_setting('maintenance_work_mem'),"
            " current_setting('max_parallel_maintenance_workers')",
        )
        return cursor.fetchone()


class HistoryLookupIndexBuildSpeedTest(DojoTestCase):

    """
    A concurrent build of a history index gets the memory and workers to build fast, and the largest tables go last.

    On a large instance the Finding event table is gigabytes, and the default maintenance_work_mem (64 MB on
    managed Postgres) both spills the build's sort to disk and, at 32 MB a participant, leaves Postgres one
    parallel worker at most. The upgrade then waited on each of those builds for most of an hour.
    """

    migration_name = "0307_event_history_lookup_indexes"

    def _operation_class(self):
        return importlib.import_module(f"dojo.db_migrations.{self.migration_name}").AddHistoryLookupIndexes

    def _record_concurrent_build(self, operation):
        """Run ``_add`` down its concurrent path with the build itself replaced; the session settings it ran under."""
        event_model = core.event_models(tracks_model=apps.get_model("dojo", "Finding"))[0]
        index = mock.Mock()
        index.name = "dojo_test_build_speed_hist"
        operation.plain_build_max_bytes = -1  # every table counts as large: build CONCURRENTLY
        seen = {}
        with connection.schema_editor(atomic=False) as schema_editor:

            def recording_add_index(model, idx, *, concurrently=False):
                seen["concurrently"] = concurrently
                seen["settings"] = _session_settings()

            with mock.patch.object(schema_editor, "add_index", side_effect=recording_add_index):
                operation._add(schema_editor, event_model, index)
        return seen

    def test_a_concurrent_build_runs_with_more_memory_and_workers_and_restores_the_session(self):
        with connection.cursor() as cursor:
            cursor.execute("SET maintenance_work_mem = '64MB'")
            cursor.execute("SET max_parallel_maintenance_workers = 2")
        before = _session_settings()

        seen = self._record_concurrent_build(self._operation_class()(indexes=[]))

        self.assertEqual({"concurrently": True, "settings": ("1h", "512MB", "4")}, seen)
        self.assertEqual(before, _session_settings())

    def test_a_session_that_already_has_more_keeps_it(self):
        with connection.cursor() as cursor:
            cursor.execute("SET maintenance_work_mem = '2GB'")
            cursor.execute("SET max_parallel_maintenance_workers = 6")

        seen = self._record_concurrent_build(self._operation_class()(indexes=[]))

        self.assertEqual(("1h", "2GB", "6"), seen["settings"])

    def test_the_largest_tables_are_built_last(self):
        operation_class = self._operation_class()
        sizes = {"dojo_findingevent": 6 * 1024**3, "dojo_testevent": 11 * 1024**2, "dojo_productevent": 3 * 1024**2}
        indexes = [
            ("findingevent", mock.Mock(name="finding_a")),
            ("testevent", mock.Mock(name="test_a")),
            ("findingevent", mock.Mock(name="finding_b")),
            ("productevent", mock.Mock(name="product_a")),
        ]
        operation = operation_class(indexes=indexes)
        to_state = mock.Mock()
        to_state.apps.get_model.side_effect = lambda _app, name: mock.Mock(_meta=mock.Mock(db_table=f"dojo_{name}"))
        schema_editor = mock.Mock()
        schema_editor.connection.vendor = "postgresql"
        schema_editor.connection.in_atomic_block = False
        built = []

        with (
            mock.patch.object(operation_class, "allow_migrate_model", return_value=True),
            mock.patch.object(
                operation_class, "_table_bytes", side_effect=lambda _se, model: sizes[model._meta.db_table],
            ),
            mock.patch.object(operation_class, "_add", side_effect=lambda _se, _model, index: built.append(index)),
        ):
            operation.database_forwards("dojo", schema_editor, from_state=None, to_state=to_state)

        # Smallest table first; a table's own indexes keep the migration's order.
        self.assertEqual([indexes[3][1], indexes[1][1], indexes[0][1], indexes[2][1]], built)


HELD_INDEX = "dojo_findingevt_test_hist"
HELD_BUILDER_APPLICATION_NAME = "unittest_0307_builder"
HELD_LOCK_KEY = 307_0307
HELD_FUNCTION = "unittest_0307_hold_build"
HELD_WAIT_TIMEOUT_SECONDS = 30


def _held_index():
    """Return (oid, indisvalid, table) for HELD_INDEX, or None when it does not exist."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT i.indexrelid::bigint, i.indisvalid, i.indrelid::regclass::text"
            " FROM pg_index i WHERE i.indexrelid = to_regclass(%s)",
            [HELD_INDEX],
        )
        return cursor.fetchone()


def _execute(sql):
    with connection.cursor() as cursor:
        cursor.execute(sql)


# Regression: 0307 dropped an index whose concurrent build had ended its progress row but not committed.
class HistoryLookupIndexBuildCommitTest(SimpleTestCase):

    """
    A re-run of ``dojo.0307`` keeps an index whose concurrent build is about to commit.

    CREATE INDEX CONCURRENTLY cannot run inside a transaction, so this runs on autocommit connections
    (a TestCase wraps each test in one) and puts the index back afterwards.
    """

    databases = {"default"}
    migration_key = ("dojo", "0307_event_history_lookup_indexes")

    def setUp(self):
        super().setUp()
        self.migration_module = importlib.import_module(f"dojo.db_migrations.{self.migration_key[1]}")
        self.operation = self.migration_module.AddHistoryLookupIndexes(
            indexes=[("findingevent", models.Index(fields=["test"], name=HELD_INDEX))],
        )
        self.state = MigrationLoader(connection).project_state(self.migration_key)
        self.addCleanup(self._run_operation)  # leaves the index valid, whatever the test did to it

    def _run_operation(self):
        with connection.schema_editor(atomic=False) as editor:
            self.operation.database_forwards("dojo", editor, self.state, self.state)

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
        _execute(f"DROP INDEX IF EXISTS {HELD_INDEX}")
        params = connection.get_connection_params()
        build_error = []

        lock_holder = psycopg.connect(**params, autocommit=True)
        self.addCleanup(lock_holder.close)  # also releases the lock if the test fails early
        lock_holder.execute("SELECT pg_advisory_lock(%s)", [HELD_LOCK_KEY])
        _execute(
            f"CREATE FUNCTION {HELD_FUNCTION}() RETURNS event_trigger LANGUAGE plpgsql AS $$"
            f" BEGIN IF current_setting('application_name') = '{HELD_BUILDER_APPLICATION_NAME}' THEN"
            f" PERFORM pg_advisory_xact_lock({HELD_LOCK_KEY}); END IF; END $$",
        )
        self.addCleanup(_execute, f"DROP FUNCTION {HELD_FUNCTION}()")
        _execute(
            f"CREATE EVENT TRIGGER {HELD_FUNCTION} ON ddl_command_end"
            f" WHEN TAG IN ('CREATE INDEX') EXECUTE FUNCTION {HELD_FUNCTION}()",
        )
        self.addCleanup(_execute, f"DROP EVENT TRIGGER {HELD_FUNCTION}")

        def build():
            try:
                with psycopg.connect(**params, autocommit=True, application_name=HELD_BUILDER_APPLICATION_NAME) as builder:
                    builder.execute(f"CREATE INDEX CONCURRENTLY {HELD_INDEX} ON dojo_findingevent (test_id)")
            except Exception as error:  # reported by the assertion on build_error below
                build_error.append(error)

        builder_thread = threading.Thread(target=build)
        builder_thread.start()
        self.addCleanup(builder_thread.join, HELD_WAIT_TIMEOUT_SECONDS)
        self.addCleanup(lock_holder.execute, "SELECT pg_advisory_unlock_all()")
        with connection.cursor() as cursor:
            deadline = time.monotonic() + HELD_WAIT_TIMEOUT_SECONDS
            while True:
                cursor.execute(
                    "SELECT 1 FROM pg_stat_activity WHERE application_name = %s"
                    " AND wait_event_type = 'Lock' AND wait_event = 'advisory'",
                    [HELD_BUILDER_APPLICATION_NAME],
                )
                if cursor.fetchone() is not None:
                    break
                self.assertLess(time.monotonic(), deadline, "the build never reached its event trigger")
                self.assertTrue(builder_thread.is_alive(), build_error)
                time.sleep(0.05)
            # The state the migration meets in that window: no progress row, and not valid yet.
            cursor.execute(
                "SELECT 1 FROM pg_stat_progress_create_index WHERE index_relid = to_regclass(%s)", [HELD_INDEX],
            )
            self.assertIsNone(cursor.fetchone(), "the build's progress row should have ended")
        in_flight_oid, valid, _ = _held_index()
        self.assertFalse(valid, "the build's commit should still be held back")

        # The build is let commit from inside the wait, the first time the operation sleeps.
        sleeps = []

        def sleep(seconds):
            sleeps.append(seconds)
            if len(sleeps) == 1:
                lock_holder.execute("SELECT pg_advisory_unlock(%s)", [HELD_LOCK_KEY])
                builder_thread.join(HELD_WAIT_TIMEOUT_SECONDS)

        dropped = []

        def refuse_drop(execute, sql, params, many, context):
            if str(sql).lstrip().upper().startswith("DROP INDEX"):
                # Refused rather than run: the drop would wait on the held build and hang.
                dropped.append(str(sql))
                msg = f"dropped an index whose build had not committed yet: {sql}"
                raise AssertionError(msg)
            return execute(sql, params, many, context)

        with (
            connection.execute_wrapper(refuse_drop),
            mock.patch.object(self.migration_module, "time", mock.Mock(sleep=sleep, monotonic=time.monotonic)),
            connection.schema_editor(atomic=False) as editor,
        ):
            self.operation.database_forwards("dojo", editor, self.state, self.state)

        self.assertEqual([], dropped)
        self.assertEqual(1, len(sleeps))
        builder_thread.join(HELD_WAIT_TIMEOUT_SECONDS)
        self.assertEqual([], build_error)
        self.assertEqual((in_flight_oid, True, "dojo_findingevent"), _held_index())
