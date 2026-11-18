"""
Migration 0304 must not re-render the migration state once per state operation.

``migrate`` renders every model before the first migration, and each state operation then
re-renders the model it changes and its relatives. Proxies of auto-created many-to-many tables
are left out of that re-render and keep the previous copies of the models alive, so 0304's 102
state operations grew the process by about 700 MB, and an initializer with a 1 GiB memory limit
was OOM-killed later in the same run. 0304 applies its state operations with the models
unrendered, so Django renders the state once afterwards.

These tests pin that, and that the wrapper changes nothing else: the resulting state matches the
plain operations, and the database work is still the frozen SQL alone.
"""

import importlib
from unittest import mock

from django.db import migrations
from django.db.migrations.loader import MigrationLoader
from django.db.migrations.state import StateApps
from django.test import SimpleTestCase

BEFORE = ("dojo", "0303_system_settings_install_id")
TARGET = ("dojo", "0304_archive_columns")


def _shape(state):
    """Each model's full field definitions, triggers and indexes: everything 0304 changes."""
    return {
        key: (
            {name: field.deconstruct()[1:] for name, field in model.fields.items()},
            {trigger.name: trigger.deconstruct() for trigger in model.options.get("triggers", ())},
            {index.name: index.deconstruct() for index in model.options.get("indexes", ())},
        )
        for key, model in state.models.items()
    }


class TestMigration0304StateRendering(SimpleTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.loader = MigrationLoader(connection=None, ignore_no_migrations=True)
        cls.migration = cls.loader.graph.nodes[TARGET]

    def rendered_state_before(self):
        state = self.loader.project_state(BEFORE, at_end=True)
        state.apps  # noqa: B018 - render every model, as the executor does before the first migration
        return state

    def test_state_operations_do_not_rerender_per_operation(self):
        state = self.rendered_state_before()
        (separate,) = self.migration.operations
        with mock.patch.object(StateApps, "render_multiple", autospec=True, wraps=StateApps.render_multiple) as render:
            separate.state_forwards("dojo", state)
            renders_during_operations = render.call_count
        self.assertEqual(
            renders_during_operations,
            0,
            msg=f"0304's state operations re-rendered models {renders_during_operations} times; expected none",
        )

    def test_state_matches_the_plain_operations(self):
        (separate,) = self.migration.operations
        (batch,) = separate.state_operations
        self.assertEqual(len(batch.operations), 102)
        wrapped = self.rendered_state_before()
        separate.state_forwards("dojo", wrapped)

        plain = self.loader.project_state(BEFORE, at_end=True)
        for operation in batch.operations:
            operation.state_forwards("dojo", plain)

        # ModelState equality also compares options 0304 does not touch, some of which only
        # compare by identity. Compare the full definitions of what 0304 changes.
        self.assertEqual(_shape(wrapped), _shape(plain))
        finding = wrapped.apps.get_model("dojo", "finding")
        self.assertEqual(finding._meta.get_field("archived_at").get_internal_type(), "DateTimeField")

    def test_database_work_is_the_frozen_sql_alone(self):
        module = importlib.import_module(f"dojo.db_migrations.{TARGET[1]}")
        (separate,) = self.migration.operations
        (run_sql,) = separate.database_operations
        self.assertIsInstance(run_sql, migrations.RunSQL)
        self.assertEqual(run_sql.sql, [module.FORWARD_SQL])
        self.assertEqual(run_sql.reverse_sql, [module.BACKWARD_SQL])
