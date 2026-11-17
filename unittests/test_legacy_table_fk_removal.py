"""
Deleting an object a removed feature's leftover row still references must commit.

Regression: deleting a Product, Engagement, Test, Finding, Development_Environment, Note or
User failed at COMMIT with a foreign-key IntegrityError (a 500) when a row in a table of a
removed feature still pointed at it.

0265_remove_stub_finding and 0266_remove_credential_manager removed Stub_Finding and the
Credential Manager models from Django's state only, so their tables (dojo_stub_finding,
dojo_cred_user, dojo_cred_mapping, dojo_cred_user_notes, dojo_cred_userevent) stayed in the
database with their DEFERRABLE INITIALLY DEFERRED foreign keys into live tables. No model
declares those tables any more, so neither the ORM collector nor the async delete's cascade
walker clears their rows, and the deferred check fails when the transaction commits.
0310_drop_legacy_table_foreign_keys drops those constraints and keeps the tables and rows.

A TestCase never commits, so each test forces the deferred checks with
SET CONSTRAINTS ALL IMMEDIATE, which raises exactly what the COMMIT would.
"""

import importlib
from contextlib import contextmanager
from unittest import mock

from django.contrib.auth.models import User
from django.db import DEFAULT_DB_ALIAS, OperationalError, connection, connections, transaction
from django.utils import timezone

from dojo.models import (
    Development_Environment,
    Engagement,
    Finding,
    Notes,
    Product,
    Product_Type,
    Test,
    Test_Type,
)
from dojo.utils import _async_delete_object  # noqa: PLC2701

from .dojo_test_case import DojoTestCase

LEGACY_TABLES = (
    "dojo_cred_mapping",
    "dojo_cred_user",
    "dojo_cred_user_notes",
    "dojo_cred_userevent",
    "dojo_stub_finding",
)


def _execute(sql, params=None):
    with connection.cursor() as cursor:
        cursor.execute(sql, params)
        return cursor.fetchall() if cursor.description else None


def _legacy_foreign_keys():
    """Every FK constraint a legacy table owns, as (table, constraint name)."""
    return _execute(
        "SELECT c.conrelid::regclass::text, c.conname FROM pg_constraint c"
        " WHERE c.contype = 'f' AND c.conrelid IN"
        " (SELECT to_regclass(t) FROM unnest(%s::text[]) t)"
        " ORDER BY 1, 2",
        [list(LEGACY_TABLES)],
    )


class _RollbackError(Exception):
    pass


@contextmanager
def _rolled_back():
    """A savepoint that is always rolled back, so one sub-test's rows never reach the next."""
    try:
        with transaction.atomic():
            yield
            raise _RollbackError
    except _RollbackError:
        pass


def _check_deferred_constraints():
    """
    Raise now what the COMMIT would raise.

    SET CONSTRAINTS lasts until the transaction ends, not the savepoint, and a TestCase runs
    its tests in one class-level transaction: put the constraints back to deferred afterwards,
    or the next test runs its deletes with every constraint checked per statement.
    """
    try:
        _execute("SET CONSTRAINTS ALL IMMEDIATE")
    finally:
        _execute("SET CONSTRAINTS ALL DEFERRED")


class LegacyRowsMixin:

    def _tree(self):
        product_type = Product_Type.objects.create(name="legacy fk type")
        product = Product.objects.create(name="legacy fk product", description="d", prod_type=product_type)
        engagement = Engagement.objects.create(
            name="legacy fk engagement", product=product,
            target_start=timezone.now(), target_end=timezone.now(),
        )
        test = Test.objects.create(
            engagement=engagement, test_type=Test_Type.objects.get_or_create(name="legacy fk scan")[0],
            target_start=timezone.now(), target_end=timezone.now(),
        )
        reporter = User.objects.create(username="legacy-fk-reporter")
        finding = Finding.objects.create(test=test, title="legacy fk finding", severity="High", reporter=reporter)
        return product, engagement, test, finding

    def _cred_user(self, environment=None):
        environment = environment or Development_Environment.objects.create(name="legacy fk environment")
        return _execute(
            "INSERT INTO dojo_cred_user (name, username, password, role, authentication, http_authentication,"
            " description, url, login_regex, logout_regex, is_valid, environment_id)"
            " VALUES ('legacy fk cred', 'u', 'p', 'r', 'Form', NULL, '', 'https://example.com', '', '', true, %s)"
            " RETURNING id",
            [environment.id],
        )[0][0]

    def _cred_mapping(self, cred_id, **refs):
        columns = ["is_authn_provider", "cred_id_id", *(f"{name}_id" for name in refs)]
        values = [False, cred_id, *(obj.id for obj in refs.values())]
        _execute(
            f"INSERT INTO dojo_cred_mapping ({', '.join(columns)}) VALUES ({', '.join(['%s'] * len(values))})",
            values,
        )

    def _stub_finding(self, test, reporter):
        _execute(
            "INSERT INTO dojo_stub_finding (title, date, severity, description, test_id, reporter_id)"
            " VALUES ('legacy fk stub', CURRENT_DATE, 'High', '', %s, %s)",
            [test.id, reporter.id],
        )


class TestLegacyTableForeignKeysAreGone(DojoTestCase):

    def test_no_legacy_table_owns_a_foreign_key(self):
        self.assertEqual(_legacy_foreign_keys(), [], "a removed feature's table still holds a foreign key")

    def test_the_legacy_tables_and_their_rows_stay(self):
        present = _execute(
            "SELECT t FROM unnest(%s::text[]) t WHERE to_regclass(t) IS NOT NULL", [list(LEGACY_TABLES)],
        )
        self.assertEqual(sorted(row[0] for row in present), sorted(LEGACY_TABLES))


class TestLegacyRowsDoNotBlockDeletes(LegacyRowsMixin, DojoTestCase):

    def _assert_deleted(self, model, pk):
        with transaction.atomic():
            _check_deferred_constraints()
        self.assertFalse(model.objects.filter(pk=pk).exists(), f"{model.__name__} {pk} survived")

    def _orm_and_async(self):
        return (
            ("orm", lambda obj: obj.delete()),
            ("async_delete", lambda obj: _async_delete_object(obj._meta.label_lower, obj.pk)),
        )

    def test_cred_mapping_rows_do_not_block_deleting_what_they_reference(self):
        for path, delete in self._orm_and_async():
            for target in ("product", "engagement", "test", "finding"):
                with self.subTest(path=path, target=target), _rolled_back():
                    product, engagement, test, finding = self._tree()
                    objs = {"product": product, "engagement": engagement, "test": test, "finding": finding}
                    obj = objs[target]
                    pk = obj.pk  # Model.delete() clears obj.pk
                    self._cred_mapping(self._cred_user(), **{target: obj})
                    delete(obj)
                    self._assert_deleted(type(obj), pk)
                    left = _execute(f"SELECT count(*) FROM dojo_cred_mapping WHERE {target}_id = %s", [pk])[0][0]
                    self.assertEqual(left, 1, "the legacy row is kept, not deleted")

    def test_cred_user_row_does_not_block_deleting_its_environment(self):
        environment = Development_Environment.objects.create(name="legacy fk referenced environment")
        self._cred_user(environment)
        pk = environment.pk
        environment.delete()
        self._assert_deleted(type(environment), pk)

    def test_cred_user_note_link_does_not_block_deleting_the_note(self):
        author = User.objects.create(username="legacy-fk-author")
        note = Notes.objects.create(entry="legacy fk note", author=author)
        _execute(
            "INSERT INTO dojo_cred_user_notes (cred_user_id, notes_id) VALUES (%s, %s)", [self._cred_user(), note.id],
        )
        pk = note.pk
        note.delete()
        self._assert_deleted(type(note), pk)

    def test_stub_finding_does_not_block_deleting_its_test(self):
        for path, delete in self._orm_and_async():
            with self.subTest(path=path), _rolled_back():
                _, _, test, finding = self._tree()
                self._stub_finding(test, finding.reporter)
                pk = test.pk
                delete(test)
                self._assert_deleted(Test, pk)

    def test_stub_finding_does_not_block_deleting_its_reporter(self):
        _, _, test, _ = self._tree()
        reporter = User.objects.create(username="legacy-fk-stub-reporter")
        self._stub_finding(test, reporter)
        pk = reporter.pk
        reporter.delete()
        self._assert_deleted(type(reporter), pk)


class TestMigration0310(DojoTestCase):

    """The migration's database work, run against the catalog states an upgrade can meet."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.migration = importlib.import_module("dojo.db_migrations.0310_drop_legacy_table_foreign_keys")

    def _run(self):
        with connection.schema_editor() as editor:
            self.migration.drop_legacy_foreign_keys(None, editor)

    def _add_legacy_foreign_key(self):
        _execute(
            "ALTER TABLE dojo_cred_mapping ADD CONSTRAINT legacy_fk_probe FOREIGN KEY (product_id)"
            " REFERENCES dojo_product (id) DEFERRABLE INITIALLY DEFERRED NOT VALID",
        )

    def test_drops_every_foreign_key_a_legacy_table_owns(self):
        self._add_legacy_foreign_key()
        _execute(
            "ALTER TABLE dojo_stub_finding ADD CONSTRAINT legacy_fk_probe_2 FOREIGN KEY (test_id)"
            " REFERENCES dojo_test (id) DEFERRABLE INITIALLY DEFERRED NOT VALID",
        )
        self.assertEqual(len(_legacy_foreign_keys()), 2)
        self._run()
        self.assertEqual(_legacy_foreign_keys(), [])

    def test_runs_again_with_nothing_left_to_drop(self):
        self._run()
        self.assertEqual(_legacy_foreign_keys(), [])

    def test_skips_a_legacy_table_that_does_not_exist(self):
        self._add_legacy_foreign_key()
        _execute("DROP TABLE dojo_stub_finding")
        self._run()
        self.assertEqual(_legacy_foreign_keys(), [])

    def test_leaves_foreign_keys_of_live_tables_alone(self):
        before = _execute("SELECT count(*) FROM pg_constraint WHERE contype = 'f'")[0][0]
        self._add_legacy_foreign_key()
        self._run()
        self.assertEqual(_execute("SELECT count(*) FROM pg_constraint WHERE contype = 'f'")[0][0], before)

    def _hold_a_lock_on_dojo_product(self):
        """Another session's open transaction holding a lock the drop has to wait for. Returns its release."""
        blocker = connections.create_connection(DEFAULT_DB_ALIAS)
        self.addCleanup(blocker.close)
        with blocker.cursor() as cursor:
            cursor.execute("BEGIN")
            cursor.execute("LOCK TABLE dojo_product IN ACCESS SHARE MODE")

        def release(*_args):
            with blocker.cursor() as cursor:
                cursor.execute("ROLLBACK")

        return release

    def test_retries_a_drop_that_cannot_get_its_lock(self):
        self._add_legacy_foreign_key()
        release = self._hold_a_lock_on_dojo_product()
        with (
            mock.patch.object(self.migration, "LOCK_TIMEOUT", "50ms"),
            mock.patch.object(self.migration, "time") as clock,
        ):
            # The wait between attempts is where the other transaction ends.
            clock.sleep.side_effect = release
            self._run()
        self.assertEqual(clock.sleep.call_count, 1, "the first attempt should time out on the lock, the second succeed")
        self.assertEqual(_legacy_foreign_keys(), [])

    def test_gives_up_after_the_last_attempt_and_a_rerun_finishes(self):
        self._add_legacy_foreign_key()
        release = self._hold_a_lock_on_dojo_product()
        with (
            mock.patch.object(self.migration, "LOCK_TIMEOUT", "50ms"),
            mock.patch.object(self.migration, "ATTEMPTS", 2),
            mock.patch.object(self.migration, "time") as clock,
            self.assertRaises(OperationalError) as raised,
        ):
            self._run()
        message = str(raised.exception)
        # The operator is told what could not be dropped, why, and that running migrate again is safe.
        self.assertIn("legacy_fk_probe on dojo_cred_mapping", message)
        self.assertIn("2 attempts of 50ms", message)
        self.assertIn("Run migrate again", message)
        self.assertEqual(raised.exception.__cause__.__cause__.sqlstate, "55P03", "the lock timeout is the cause")
        self.assertEqual(clock.sleep.call_count, 1)
        self.assertEqual(len(_legacy_foreign_keys()), 1, "a drop that never got its lock leaves the constraint")
        # Once the other transaction ends, a re-run drops what is left.
        release()
        self._run()
        self.assertEqual(_legacy_foreign_keys(), [])
