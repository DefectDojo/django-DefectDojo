"""Tests for the release schema snapshot (dojo/management/commands/schema_snapshot.py)."""
import io
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import CommandError, call_command
from django.db import connection
from django.test import SimpleTestCase, TestCase

from dojo.management.commands import schema_snapshot
from dojo.management.commands.complete_initialization import Command as InitializeCommand
from dojo.management.commands.schema_snapshot import (
    MANIFEST_FORMAT,
    disk_migrations,
    executable_sql,
    known_migrations,
    load_schema_snapshot_if_empty,
    manifest_problem,
    migration_digests,
)


def manifest_for(migrations, **overrides):
    """A manifest exactly as this code would write it for a database with every migration applied."""
    manifest = {
        "format": MANIFEST_FORMAT,
        "release": "test",
        "postgres": 160000,
        "applied": sorted(known_migrations(migrations)),
        "digests": migration_digests(migrations),
    }
    manifest.update(overrides)
    return manifest


class _Output:

    """The slice of a management command the loader writes to."""

    def __init__(self):
        self.stdout = io.StringIO()


class TestManifestProblem(SimpleTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.migrations = disk_migrations()

    def test_a_manifest_of_this_code_fits(self):
        self.assertIsNone(manifest_problem(manifest_for(self.migrations), self.migrations, 180000))

    def test_an_older_release_fits(self):
        # The release before the newest dojo migration: the initializer loads it and migrates the rest.
        manifest = manifest_for(self.migrations)
        newest = max(entry for entry in manifest["applied"] if entry.startswith("dojo.0"))
        manifest["applied"].remove(newest)
        manifest["digests"].pop(newest, None)
        self.assertIsNone(manifest_problem(manifest, self.migrations))

    def test_a_migration_this_code_does_not_ship_is_refused(self):
        manifest = manifest_for(self.migrations)
        manifest["applied"].append("dojo.9999_from_a_newer_release")
        problem = manifest_problem(manifest, self.migrations)
        self.assertIn("does not ship", problem)
        self.assertIn("dojo.9999_from_a_newer_release", problem)

    def test_a_rewritten_migration_is_refused(self):
        manifest = manifest_for(self.migrations)
        first = min(manifest["digests"])
        manifest["digests"][first] = "0" * 64
        problem = manifest_problem(manifest, self.migrations)
        self.assertIn("differ", problem)
        self.assertIn(first, problem)

    def test_an_older_server_is_refused_and_a_newer_one_is_not(self):
        manifest = manifest_for(self.migrations, postgres=160013)
        self.assertIn("PostgreSQL 16", manifest_problem(manifest, self.migrations, 150008))
        self.assertIsNone(manifest_problem(manifest, self.migrations, 160002))
        self.assertIsNone(manifest_problem(manifest, self.migrations, 180006))

    def test_an_unknown_format_is_refused(self):
        for manifest in (None, [], {"format": MANIFEST_FORMAT + 1}):
            with self.subTest(manifest=manifest):
                self.assertIn("format", manifest_problem(manifest, self.migrations))

    def test_migrations_a_squash_replaced_are_known(self):
        # Applying dojo.0001_squashed_0090 records 0001..0090 as applied too, and they have no file.
        replaced = {
            f"{app_label}.{name}"
            for migration in self.migrations.values()
            for app_label, name in getattr(migration, "replaces", None) or ()
        }
        self.assertTrue(replaced, msg="expected at least one squashed migration")
        self.assertTrue(replaced <= known_migrations(self.migrations))

    def test_only_dojo_migrations_are_digested(self):
        digests = migration_digests(self.migrations)
        self.assertTrue(digests)
        self.assertEqual({entry.split(".")[0] for entry in digests}, {"dojo"})

    def test_psql_only_lines_are_dropped(self):
        sql = "\\restrict abc\nCREATE TABLE t (id int);\nCOMMENT ON EXTENSION pg_trgm IS 'x';\n\\unrestrict abc\n"
        self.assertEqual(executable_sql(sql), "CREATE TABLE t (id int);\n")


class TestLoader(TestCase):

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())
        self.snapshot = self.directory / "migrated.sql"
        self.manifest = self.directory / "manifest.json"
        self.out = _Output()

    def write_snapshot(self, sql="CREATE TABLE schema_snapshot_probe (id integer);\n", **manifest_overrides):
        self.snapshot.write_text(sql, encoding="utf-8")
        self.manifest.write_text(json.dumps(manifest_for(disk_migrations(), **manifest_overrides)), encoding="utf-8")

    def load(self, *, empty=True):
        with (
            patch.dict(os.environ, {"DD_SCHEMA_SNAPSHOT_PATH": str(self.snapshot)}),
            patch.object(schema_snapshot, "database_is_empty", return_value=empty),
            # The loader closes the connection after a load; inside a test that would end the test's transaction.
            patch.object(connection, "close"),
        ):
            return load_schema_snapshot_if_empty(self.out)

    def table_exists(self):
        with connection.cursor() as cursor:
            return "schema_snapshot_probe" in connection.introspection.table_names(cursor)

    def test_no_snapshot_touches_no_database(self):
        # What keeps images without a snapshot (development, CI-built OSS images inside DefectDojo Pro's
        # tests) exactly as before: not a single query.
        for value in ("", str(self.directory / "missing.sql")):
            with self.subTest(path=value), patch.dict(os.environ, {"DD_SCHEMA_SNAPSHOT_PATH": value}), self.assertNumQueries(0):
                self.assertFalse(load_schema_snapshot_if_empty(self.out))
        self.assertEqual(self.out.stdout.getvalue(), "")

    def test_a_database_with_tables_is_left_alone_silently(self):
        self.write_snapshot()
        self.assertFalse(self.load(empty=False))
        self.assertFalse(self.table_exists())
        self.assertEqual(self.out.stdout.getvalue(), "")

    def test_an_empty_database_gets_the_snapshot(self):
        self.write_snapshot()
        with patch.object(connection.introspection, "table_names", return_value=[]):
            loaded = self.load()
        self.assertTrue(loaded)
        self.assertTrue(self.table_exists())
        self.assertIn("Loaded the schema snapshot", self.out.stdout.getvalue())

    def test_a_snapshot_that_does_not_fit_is_reported_and_skipped(self):
        self.write_snapshot(applied=["dojo.9999_from_a_newer_release"])
        self.assertFalse(self.load())
        self.assertFalse(self.table_exists())
        self.assertIn("Not loading the schema snapshot", self.out.stdout.getvalue())
        self.assertIn("does not ship", self.out.stdout.getvalue())

    def test_a_snapshot_without_a_manifest_is_skipped(self):
        self.write_snapshot()
        self.manifest.unlink()
        self.assertFalse(self.load())
        self.assertIn("not in a format", self.out.stdout.getvalue())

    def test_a_concurrent_initializer_that_loaded_first_wins(self):
        # The table check under the advisory lock sees the other initializer's tables.
        self.write_snapshot()
        self.assertFalse(self.load())
        self.assertFalse(self.table_exists())
        self.assertIn("Another initializer loaded", self.out.stdout.getvalue())


class TestSchemaSnapshotCommand(TestCase):

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())
        self.manifest = self.directory / "manifest.json"

    def test_a_written_manifest_passes_its_own_check(self):
        call_command("schema_snapshot", write_manifest=str(self.manifest), stdout=io.StringIO())
        written = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertEqual(written["format"], MANIFEST_FORMAT)
        self.assertIn("dojo.0001_squashed_0090_index_duplicate_finding", written["applied"])
        out = io.StringIO()
        call_command("schema_snapshot", check=str(self.manifest), stdout=out)
        self.assertIn("fits this code", out.getvalue())

    def test_a_database_with_a_user_is_not_described(self):
        get_user_model().objects.create(username="someone")
        with self.assertRaisesRegex(CommandError, "users"):
            call_command("schema_snapshot", write_manifest=str(self.manifest), stdout=io.StringIO())
        self.assertFalse(self.manifest.exists())

    def test_check_refuses_an_unfitting_or_unreadable_manifest(self):
        self.manifest.write_text(json.dumps(manifest_for(disk_migrations(), applied=["dojo.9999_newer"])), encoding="utf-8")
        with self.assertRaisesRegex(CommandError, "does not ship"):
            call_command("schema_snapshot", check=str(self.manifest), stdout=io.StringIO())
        self.manifest.write_text("not json", encoding="utf-8")
        with self.assertRaisesRegex(CommandError, "could not be read"):
            call_command("schema_snapshot", check=str(self.manifest), stdout=io.StringIO())


class TestInitializerOffersTheSnapshot(SimpleTestCase):

    def test_the_snapshot_is_offered_before_migrate(self):
        order = []
        command = InitializeCommand(stdout=io.StringIO(), stderr=io.StringIO())
        with (
            patch.dict(os.environ, {"DD_INITIALIZE": "true"}),
            patch.object(InitializeCommand, "check_enable_auditlog_consistency"),
            patch.object(InitializeCommand, "warn_on_missing_migrations"),
            patch(
                "dojo.management.commands.complete_initialization.load_schema_snapshot_if_empty",
                side_effect=lambda *_args, **_kwargs: order.append("snapshot"),
            ),
            patch(
                "dojo.management.commands.complete_initialization.call_command",
                side_effect=lambda name, *_args, **_kwargs: order.append(name),
            ),
            patch("dojo.management.commands.complete_initialization.configure_pghistory_triggers"),
            patch.object(InitializeCommand, "admin_user_exists", return_value=True),
        ):
            command.handle()
        self.assertEqual(order[:2], ["snapshot", "migrate"])
