"""
An object's history is read from the pghistory event tables through indexes, not full scans.

``DojoEvents.objects.references(obj)`` reads every event table with a foreign key to ``obj``'s model,
filtering each on that key, and pghistory's copies of the keys carry no index of their own. Each
event's diff is then computed from the object's previous event, looked up by ``pgh_obj_id`` and
``pgh_id``. Without indexes for both, one finding's history read every row of the Finding event
table, and every event of the finding once per event shown: minutes on a large instance.
"""
import importlib
from unittest import mock

from django.apps import apps
from django.db import connection, migrations
from django.db.migrations.loader import MigrationLoader
from django.db.migrations.state import ProjectState
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
