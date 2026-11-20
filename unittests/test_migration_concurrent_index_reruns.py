"""
Every migration that builds an index CONCURRENTLY can be re-run after an interrupted build.

An interrupted CREATE INDEX CONCURRENTLY (the process is killed, the connection drops) leaves
its index in the catalog marked INVALID while the non-atomic migration stays unrecorded. A
plain AddIndexConcurrently then fails every retry with "relation ... already exists", and a
raw CREATE INDEX CONCURRENTLY IF NOT EXISTS keeps the INVALID index for good, so the planner
never uses it and nothing reports why. 0305 was the first migration to recover; these tests
hold every earlier one to the same guard: drop an INVALID leftover and build, keep a valid
index as it is.

The INVALID index comes from a real failed concurrent build: a unique index under the
migration's index name, over a scratch table holding a duplicate. CREATE INDEX CONCURRENTLY
cannot run inside a transaction, so these are SimpleTestCase tests on autocommit connections
(a TestCase wraps each test in one), and they put every index back afterwards.
"""

import importlib
import re
from pathlib import Path
from unittest import mock

from django.db import IntegrityError, connection, migrations
from django.db.migrations.loader import MigrationLoader
from django.test import SimpleTestCase

SCRATCH_TABLE = "unittest_concurrent_index_scratch"

# Every operation of these migrations is an index build CONCURRENTLY (0278 also enables pg_trgm).
ADD_INDEX_MIGRATIONS = (
    "0270_finding_visibility_perf_indexes",
    "0271_finding_perf_indexes",
    "0273_product_upper_name_index",
    "0274_finding_sla_expiration_index",
    "0278_global_search_fts_trigram_indexes",
    "0281_vulnerability_id_type",
    "0299_finding_test_numsev_index",
    "0300_finding_upper_title_index",
)


def _migration(name):
    return importlib.import_module(f"dojo.db_migrations.{name}").Migration


def _index(name):
    """Return (oid, indisvalid) for the index, or None when it does not exist."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT i.indexrelid::bigint, i.indisvalid FROM pg_index i WHERE i.indexrelid = to_regclass(%s)",
            [name],
        )
        return cursor.fetchone()


def _execute(sql):
    with connection.cursor() as cursor:
        cursor.execute(sql)


def _run_sql_operations(operations):
    """Run RunSQL / RunPython database operations in order, in autocommit, as migrate does."""
    with connection.schema_editor(atomic=False) as editor:
        for operation in operations:
            if hasattr(operation, "database_operations"):
                _run_sql_operations(operation.database_operations)
            elif hasattr(operation, "code"):
                operation.code(None, editor)
            elif hasattr(operation, "sql"):
                # RunSQL takes one statement or a list of them (0244).
                statements = operation.sql if isinstance(operation.sql, (list, tuple)) else [operation.sql]
                for statement in statements:
                    editor.execute(statement)


class InvalidIndexMixin:

    databases = {"default"}

    def _leave_invalid_index(self, name):
        """Leave an INVALID index called ``name``, as an interrupted build does; return its oid."""
        _execute(f'DROP INDEX IF EXISTS "{name}"')
        _execute(f"DROP TABLE IF EXISTS {SCRATCH_TABLE}")
        _execute(f"CREATE TABLE {SCRATCH_TABLE} (v integer)")
        _execute(f"INSERT INTO {SCRATCH_TABLE} VALUES (1), (1)")
        with self.assertRaises(IntegrityError):
            _execute(f'CREATE UNIQUE INDEX CONCURRENTLY "{name}" ON {SCRATCH_TABLE} (v)')
        oid, valid = _index(name)
        self.assertFalse(valid, "the failed build should leave an INVALID index")
        return oid

    def _drop_scratch_table(self):
        _execute(f"DROP TABLE IF EXISTS {SCRATCH_TABLE}")


class TestAddIndexConcurrentlyReruns(InvalidIndexMixin, SimpleTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        loader = MigrationLoader(connection)
        cls.cases = []
        for name in ADD_INDEX_MIGRATIONS:
            state = loader.project_state(("dojo", name))
            cls.cases.extend(
                (name, operation, state)
                for operation in _migration(name).operations
                if hasattr(operation, "index")
            )

    def _run(self, operation, state):
        with connection.schema_editor(atomic=False) as editor:
            operation.database_forwards("dojo", editor, state, state)

    def _put_back(self, operation, state):
        """Leave the index as the test found it: a later migration (0296) drops some of them."""
        name = operation.index.name
        row = _index(name)
        if row is not None and not row[1]:
            _execute(f'DROP INDEX IF EXISTS "{name}"')
            row = None
        if row is None and name in self.existing:
            self._run(operation, state)
        elif name not in self.existing:
            _execute(f'DROP INDEX IF EXISTS "{name}"')

    def setUp(self):
        super().setUp()
        self.existing = {op.index.name for _, op, _ in self.cases if _index(op.index.name) is not None}
        self.addCleanup(self._drop_scratch_table)

    def test_every_index_operation_is_covered(self):
        # 2 + 5 + 1 + 1 + 20 + 1 + 1 + 1 index builds.
        self.assertEqual(32, len(self.cases))

    def test_invalid_leftover_is_dropped_and_rebuilt(self):
        for name, operation, state in self.cases:
            with self.subTest(migration=name, index=operation.index.name):
                self.addCleanup(self._put_back, operation, state)
                leftover_oid = self._leave_invalid_index(operation.index.name)

                self._run(operation, state)

                oid, valid = _index(operation.index.name)
                self.assertTrue(valid)
                self.assertNotEqual(leftover_oid, oid, "the INVALID leftover was rebuilt, not kept")

    def test_valid_index_is_kept(self):
        for name, operation, state in self.cases:
            with self.subTest(migration=name, index=operation.index.name):
                self.addCleanup(self._put_back, operation, state)
                if _index(operation.index.name) is None:
                    self._run(operation, state)
                before = _index(operation.index.name)
                self.assertTrue(before[1])

                self._run(operation, state)

                self.assertEqual(before, _index(operation.index.name), "a valid index is kept, not rebuilt")

    def test_missing_index_is_built(self):
        _, operation, state = self.cases[0]
        self.addCleanup(self._put_back, operation, state)
        _execute(f'DROP INDEX IF EXISTS "{operation.index.name}"')

        self._run(operation, state)

        self.assertTrue(_index(operation.index.name)[1])


class TestVulnerabilityIdUpperIndexRerun(InvalidIndexMixin, SimpleTestCase):

    """0280 builds with IF NOT EXISTS, which alone would keep an INVALID leftover for good."""

    INDEX = "dojo_vulnid_upper_idx"

    def setUp(self):
        super().setUp()
        self.operations = _migration("0280_vulnerability_id_upper_index").operations
        self.addCleanup(_run_sql_operations, self.operations)

    def test_invalid_leftover_is_dropped_and_rebuilt(self):
        leftover_oid = self._leave_invalid_index(self.INDEX)

        _run_sql_operations(self.operations)

        oid, valid = _index(self.INDEX)
        self.assertTrue(valid)
        self.assertNotEqual(leftover_oid, oid)
        self._drop_scratch_table()

    def test_valid_index_is_kept(self):
        before = _index(self.INDEX)

        _run_sql_operations(self.operations)

        self.assertEqual(before, _index(self.INDEX))


class TestUniqueFindingVulnerabilityIdRerun(InvalidIndexMixin, SimpleTestCase):

    """
    0283 builds a unique index with IF NOT EXISTS, then adopts it as a constraint.

    A build interrupted before the constraint was added leaves an INVALID index, which
    ADD CONSTRAINT ... USING INDEX refuses, so the re-run must rebuild it first.
    """

    INDEX = "unique_finding_vulnerability_id"
    DROP_CONSTRAINT = f"ALTER TABLE dojo_vulnerability_id DROP CONSTRAINT IF EXISTS {INDEX}"

    def setUp(self):
        super().setUp()
        self.operations = _migration("0283_unique_finding_vulnerability_id").operations
        self.addCleanup(self._restore)

    def _restore(self):
        self._drop_scratch_table()
        if self._constraint_index() is None:
            _execute(f"DROP INDEX IF EXISTS {self.INDEX}")
            _run_sql_operations(self.operations)

    def _constraint_index(self):
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT conindid::bigint FROM pg_constraint WHERE conname = %s AND contype = 'u'",
                [self.INDEX],
            )
            row = cursor.fetchone()
        return row[0] if row else None

    def test_invalid_leftover_is_dropped_and_rebuilt_then_adopted(self):
        _execute(self.DROP_CONSTRAINT)  # the interrupted run never reached ADD CONSTRAINT
        leftover_oid = self._leave_invalid_index(self.INDEX)

        _run_sql_operations(self.operations)

        oid, valid = _index(self.INDEX)
        self.assertTrue(valid)
        self.assertNotEqual(leftover_oid, oid)
        self.assertEqual(oid, self._constraint_index())

    def test_valid_index_is_kept(self):
        _execute(self.DROP_CONSTRAINT)
        # Dropping the constraint drops its index; a run that built the index and was killed
        # before ADD CONSTRAINT leaves a valid one, so build that first.
        _execute(f"CREATE UNIQUE INDEX CONCURRENTLY {self.INDEX} ON dojo_vulnerability_id (finding_id, vulnerability_id)")
        built = _index(self.INDEX)
        self.assertTrue(built[1])

        _run_sql_operations(self.operations)

        self.assertEqual(built, _index(self.INDEX), "a valid index is adopted, not rebuilt")
        self.assertEqual(built[0], self._constraint_index())


class TestPghistoryContextIndexesRerun(InvalidIndexMixin, SimpleTestCase):

    """0244 builds four indexes with IF NOT EXISTS, which alone would keep an INVALID leftover for good."""

    INDEX = "pghistory_context_user_idx"

    def setUp(self):
        super().setUp()
        self.operations = _migration("0244_pghistory_indices").operations
        self.addCleanup(self._put_back)

    def _put_back(self):
        row = _index(self.INDEX)
        if row is not None and not row[1]:
            _execute(f'DROP INDEX IF EXISTS "{self.INDEX}"')
        self._drop_scratch_table()
        _run_sql_operations(self.operations)

    def test_invalid_leftover_is_dropped_and_rebuilt(self):
        leftover_oid = self._leave_invalid_index(self.INDEX)

        _run_sql_operations(self.operations)

        oid, valid = _index(self.INDEX)
        self.assertTrue(valid)
        self.assertNotEqual(leftover_oid, oid)

    def test_valid_indexes_are_kept(self):
        before = {name: _index(name) for name in self.INDEX_NAMES}
        self.assertTrue(all(row and row[1] for row in before.values()))

        _run_sql_operations(self.operations)

        self.assertEqual(before, {name: _index(name) for name in self.INDEX_NAMES})

    INDEX_NAMES = (
        "pghistory_context_metadata_gin_idx",
        "pghistory_context_user_idx",
        "pghistory_context_remote_addr_idx",
        "pghistory_context_url_idx",
    )


class TestRepairInvalidConcurrentIndexes(InvalidIndexMixin, SimpleTestCase):

    """0313 rebuilds an index of 0244 or 0280 that a database recorded INVALID before they were fixed."""

    INDEX = "dojo_vulnid_upper_idx"

    def setUp(self):
        super().setUp()
        self.repair = importlib.import_module("dojo.db_migrations.0313_repair_invalid_concurrent_indexes")
        self.addCleanup(self._put_back)

    def _apply(self):
        _run_sql_operations(self.repair.Migration.operations)

    def _put_back(self):
        row = _index(self.INDEX)
        if row is not None and not row[1]:
            _execute(f'DROP INDEX IF EXISTS "{self.INDEX}"')
        self._drop_scratch_table()
        self._apply()

    def test_invalid_index_is_rebuilt(self):
        leftover_oid = self._leave_invalid_index(self.INDEX)

        self._apply()

        oid, valid = _index(self.INDEX)
        self.assertTrue(valid)
        self.assertNotEqual(leftover_oid, oid)

    def test_valid_indexes_are_kept(self):
        before = {name: _index(name) for name in self.repair.CONCURRENT_INDEXES}
        self.assertTrue(all(row and row[1] for row in before.values()))

        self._apply()

        self.assertEqual(before, {name: _index(name) for name in self.repair.CONCURRENT_INDEXES})

    def test_missing_index_is_built(self):
        _execute(f'DROP INDEX "{self.INDEX}"')

        self._apply()

        self.assertTrue(_index(self.INDEX)[1])

    def test_repair_builds_what_the_original_migrations_build(self):
        """The repair restates each build as a literal; it must match the original statement."""
        originals = []
        for operation in _migration("0244_pghistory_indices").operations:
            if hasattr(operation, "sql"):
                originals.extend(statement.rstrip(";") for statement in operation.sql)
        (separate,) = _migration("0280_vulnerability_id_upper_index").operations
        originals.extend(op.sql for op in separate.database_operations if hasattr(op, "sql"))
        self.assertEqual(sorted(originals), sorted(self.repair.CONCURRENT_INDEXES.values()))

    def test_is_non_atomic_and_reverses_to_nothing(self):
        self.assertFalse(self.repair.Migration.atomic)
        (operation,) = self.repair.Migration.operations
        self.assertIs(migrations.RunPython.noop, operation.reverse_code)


class TestEveryConcurrentIndexBuildIsGuarded(SimpleTestCase):

    """
    A migration that builds an index CONCURRENTLY must check indisvalid, so a re-run recovers.

    A new migration that adds a bare AddIndexConcurrently, or a CREATE INDEX CONCURRENTLY
    without a validity check, fails here. Copy the guard from 0305 (AddIndexConcurrentlyIfMissing)
    or 0280 (drop_index_if_invalid) into it: a migration must not import live code.
    """

    BUILDS_CONCURRENTLY = re.compile(r"AddIndexConcurrently\(|CREATE\s+(UNIQUE\s+)?INDEX\s+CONCURRENTLY", re.IGNORECASE)
    # Files whose only concurrent build is undoing a drop, which a re-run never meets.
    EXEMPT = {
        "0296_drop_unused_finding_indexes.py": "builds only in reverse_sql, to restore indexes it dropped",
    }

    def test_every_concurrent_build_checks_indisvalid(self):
        directory = Path(importlib.import_module("dojo.db_migrations").__file__).parent
        unguarded = []
        for path in sorted(directory.glob("[0-9]*.py")):
            code = "\n".join(line for line in path.read_text().splitlines() if not line.lstrip().startswith("#"))
            if self.BUILDS_CONCURRENTLY.search(code) and "indisvalid" not in code and path.name not in self.EXEMPT:
                unguarded.append(path.name)
        self.assertEqual([], unguarded)

    def test_exemptions_still_exist(self):
        directory = Path(importlib.import_module("dojo.db_migrations").__file__).parent
        for name in self.EXEMPT:
            self.assertTrue((directory / name).is_file(), name)


class TestVulnerabilityIdTypeColumnRerun(SimpleTestCase):

    """0281 adds its column before the concurrent build, so a re-run after a killed build meets the column."""

    databases = {"default"}

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.state = MigrationLoader(connection).project_state(("dojo", "0281_vulnerability_id_type"))
        cls.operation = _migration("0281_vulnerability_id_type").operations[0]
        model = cls.state.apps.get_model("dojo", "vulnerability_id")
        field = model._meta.get_field("vulnerability_id_type")
        with connection.schema_editor(collect_sql=True) as editor:
            cls.index_sql = [str(statement) for statement in editor._field_indexes_sql(model, field)]
            cls.index_names = [str(statement.parts["name"]) for statement in editor._field_indexes_sql(model, field)]

    def _forwards(self, **editor_kwargs):
        with connection.schema_editor(atomic=False, **editor_kwargs) as editor:
            self.operation.database_forwards("dojo", editor, self.state, self.state)
        return editor

    def test_field_has_indexes_to_restore(self):
        # db_index on a CharField: the plain index and the varchar_pattern_ops one.
        self.assertEqual(2, len(self.index_names))
        for name in self.index_names:
            self.assertIsNotNone(_index(name), name)

    def test_existing_column_and_indexes_are_kept(self):
        before = {name: _index(name) for name in self.index_names}

        editor = self._forwards(collect_sql=True)

        self.assertEqual([], editor.collected_sql)
        self.assertEqual(before, {name: _index(name) for name in self.index_names})

    def test_missing_field_indexes_are_built(self):
        self.addCleanup(self._restore_indexes)
        for name in self.index_names:
            _execute(f"DROP INDEX {name}")

        self._forwards()

        for name in self.index_names:
            self.assertTrue(_index(name)[1], name)

    def _restore_indexes(self):
        for name, sql in zip(self.index_names, self.index_sql, strict=True):
            if _index(name) is None:
                _execute(sql)

    def test_missing_column_is_added(self):
        with mock.patch.object(connection.introspection, "get_table_description", return_value=[]):
            editor = self._forwards(collect_sql=True)
        self.assertIn('ADD COLUMN "vulnerability_id_type"', "\n".join(editor.collected_sql))
