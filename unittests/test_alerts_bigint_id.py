"""
Regression: dojo_alerts.id is a 32-bit integer, so alert creation stops once its sequence passes 2^31 - 1.

dojo_alerts is pruned to MAX_ALERTS_PER_USER per user every few hours, so the live table stays small while
its id sequence keeps climbing with every alert ever created. On a busy instance the sequence reaches the
integer maximum and every new alert fails. Alerts.id is a BigAutoField from migration 0312 on.

These tests check the column and its sequence in the migrated test database (a fresh install, which builds
an identity column), create an alert with the sequence already past the integer maximum, and run 0312 itself
against the two shapes an upgraded install can have: an integer identity column, and the integer serial column
(a sequence owned by the column, used as its default) that installs created before Django 4.1 still carry.

Everything runs inside the test's transaction, DDL included, so the schema comes back on rollback. setval is
not transactional, so each test that moves the sequence puts it back, and the insert past the integer maximum
runs in a savepoint so that cleanup still runs when the insert fails.
"""

import importlib

from django.db import connection, transaction
from django.db.migrations.loader import MigrationLoader
from django.test import TestCase

from dojo.models import Alerts

MIGRATION = ("dojo", "0312_alerts_bigint_id")
PREVIOUS = ("dojo", "0311_product_dupe_delete_held_at")
INT4_MAX = 2**31 - 1
INT8_MAX = 2**63 - 1


def _fetchone(sql, params=None):
    with connection.cursor() as cursor:
        cursor.execute(sql, params or [])
        return cursor.fetchone()


def _execute(sql, params=None):
    with connection.cursor() as cursor:
        cursor.execute(sql, params or [])


def column_type(table, column):
    return _fetchone(
        "SELECT data_type FROM information_schema.columns"
        " WHERE table_schema = current_schema() AND table_name = %s AND column_name = %s",
        [table, column],
    )[0]


def id_sequence():
    """Return the name of the sequence behind dojo_alerts.id, serial or identity."""
    return _fetchone("SELECT pg_get_serial_sequence('dojo_alerts', 'id')")[0]


def sequence_type_and_max(sequence):
    return _fetchone(
        "SELECT data_type::text, max_value FROM pg_sequences WHERE schemaname || '.' || sequencename = %s",
        [sequence],
    )


class AlertsSequenceMixin:
    def _move_sequence_past_int4(self):
        """Set the id sequence so its next value is INT4_MAX + 1, and put it back after the test."""
        sequence = id_sequence()
        last_value, is_called = _fetchone(f"SELECT last_value, is_called FROM {sequence}")
        self.addCleanup(_execute, "SELECT setval(%s, %s, %s)", [sequence, last_value, is_called])
        _execute("SELECT setval(%s, %s)", [sequence, INT4_MAX])

    def _assert_alert_past_int4(self):
        # A savepoint, so a failed insert leaves the test's transaction usable and the cleanup can reset the sequence.
        with transaction.atomic():
            alert = Alerts.objects.create(title="past int4", description="x")
        persisted = Alerts.objects.get(pk=alert.pk)
        self.assertGreater(persisted.pk, INT4_MAX, msg=f"persisted id={persisted.pk}")


class TestAlertsIdIsBigint(AlertsSequenceMixin, TestCase):
    def test_column_and_sequence_are_bigint(self):
        self.assertEqual("bigint", column_type("dojo_alerts", "id"))
        self.assertEqual(("bigint", INT8_MAX), sequence_type_and_max(id_sequence()))

    def test_alert_is_created_past_int4_max(self):
        self._move_sequence_past_int4()
        self._assert_alert_past_int4()


class TestMigration0312Upgrade(AlertsSequenceMixin, TestCase):

    """Run 0312 against an integer dojo_alerts.id, as an upgraded install has it."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.operation = importlib.import_module(f"dojo.db_migrations.{MIGRATION[1]}").Migration.operations[0]
        loader = MigrationLoader(connection)
        cls.before = loader.project_state(PREVIOUS)
        cls.after = loader.project_state(MIGRATION)

    def _downgrade_to_integer_identity(self):
        with connection.schema_editor() as editor:
            self.operation.database_backwards("dojo", editor, self.after, self.before)
        self.assertEqual("integer", column_type("dojo_alerts", "id"))
        self.assertEqual(("integer", INT4_MAX), sequence_type_and_max(id_sequence()))

    def _convert_to_integer_serial(self):
        """Replace the identity with the serial shape: an integer sequence owned by the column, as its default."""
        _execute("ALTER TABLE dojo_alerts ALTER COLUMN id DROP IDENTITY")
        _execute("CREATE SEQUENCE dojo_alerts_id_seq AS integer OWNED BY dojo_alerts.id")
        _execute("ALTER TABLE dojo_alerts ALTER COLUMN id SET DEFAULT nextval('dojo_alerts_id_seq'::regclass)")
        _execute("SELECT setval('dojo_alerts_id_seq', COALESCE((SELECT max(id) FROM dojo_alerts), 0) + 1, false)")
        is_identity = _fetchone(
            "SELECT is_identity FROM information_schema.columns WHERE table_name = 'dojo_alerts' AND column_name = 'id'",
        )[0]
        self.assertEqual("NO", is_identity)
        self.assertEqual(("integer", INT4_MAX), sequence_type_and_max(id_sequence()))

    def _migrate(self):
        with connection.schema_editor() as editor:
            self.operation.database_forwards("dojo", editor, self.before, self.after)

    def _assert_upgraded(self):
        self.assertEqual("bigint", column_type("dojo_alerts", "id"))
        self.assertEqual(("bigint", INT8_MAX), sequence_type_and_max(id_sequence()))
        self._move_sequence_past_int4()
        self._assert_alert_past_int4()

    def test_upgrade_from_integer_identity(self):
        self._downgrade_to_integer_identity()
        self._migrate()
        self._assert_upgraded()

    def test_upgrade_from_integer_serial(self):
        self._downgrade_to_integer_identity()
        self._convert_to_integer_serial()
        self._migrate()
        self._assert_upgraded()
