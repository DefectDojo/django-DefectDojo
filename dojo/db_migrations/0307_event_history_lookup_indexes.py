import time

from django.db import OperationalError, migrations, models, transaction
from django.db.migrations.operations.base import Operation


class AddHistoryLookupIndexes(Operation):

    """
    Add indexes to pghistory event tables without stopping event writes; safe to re-run.

    One operation for every index of the migration, not one each, so the migration state is updated
    once: an AddIndex per index re-renders the event model and every model related to it each time.
    With a hundred indexes those re-renders, not the index builds, took over a minute each time the
    migration was applied or unapplied, and a run that rewinds and reapplies migrations (tenancy
    migrate, its tests) paid that on every pass.

    Event tables are written by triggers on every save of the tracked model, so a build must not
    block them for long. A large table is built CONCURRENTLY. A small one is built plainly under a
    short lock_timeout: the build takes milliseconds, while CONCURRENTLY waits, twice, for every
    older transaction in the database to end. When the plain build cannot get its lock in time, the
    concurrent build runs instead. Inside a caller's transaction (a test, a tenant migrated under an
    outer atomic block) every index is built plainly, as AddIndex would.

    Nothing here waits without a bound. A concurrent build runs under lock_timeout =
    concurrent_build_lock_timeout, which also bounds its waits for older transactions; past it the
    migration fails and a re-run starts over. A build of the same index still running elsewhere (a
    killed run's backend) is waited for at most concurrent_build_wait_seconds. A re-run keeps a
    valid index, drops an INVALID leftover of an interrupted CONCURRENTLY build and builds it again.
    Migration state is exactly what an AddIndex per index would give.
    """

    reversible = True
    plain_build_max_bytes = 64 * 1024 * 1024
    plain_build_lock_timeout = "2s"
    concurrent_build_lock_timeout = "1h"
    concurrent_build_wait_seconds = 3600
    poll_seconds = 5

    def __init__(self, indexes):
        self.indexes = indexes

    def describe(self):
        return f"Create {len(self.indexes)} indexes on pghistory event tables"

    @property
    def migration_name_fragment(self):
        return "history_lookup_indexes"

    def state_forwards(self, app_label, state):
        # ProjectState.add_index re-renders the model and every model related to it on each call;
        # append them all, then re-render the affected models once.
        model_keys = set()
        for model_name, index in self.indexes:
            model_key = (app_label, model_name.lower())
            model_state = state.models[model_key]
            model_state.options["indexes"] = [*model_state.options["indexes"], index]
            model_keys.add(model_key)
        state.reload_models(model_keys, delay=True)

    @staticmethod
    def _concurrent_allowed(schema_editor):
        connection = schema_editor.connection
        return connection.vendor == "postgresql" and not connection.in_atomic_block

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        for model_name, index in self.indexes:
            model = to_state.apps.get_model(app_label, model_name)
            if not self.allow_migrate_model(schema_editor.connection.alias, model):
                continue
            if self._concurrent_allowed(schema_editor):
                self._add(schema_editor, model, index)
            else:
                schema_editor.add_index(model, index)

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        concurrently = self._concurrent_allowed(schema_editor)
        for model_name, index in reversed(self.indexes):
            model = from_state.apps.get_model(app_label, model_name)
            if self.allow_migrate_model(schema_editor.connection.alias, model):
                schema_editor.remove_index(model, index, concurrently=concurrently)

    def _add(self, schema_editor, model, index):
        name = schema_editor.quote_name(index.name)
        with schema_editor.connection.cursor() as cursor:
            self._wait_for_other_build(cursor, index.name)
            cursor.execute("SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass(%s)", [name])
            row = cursor.fetchone()
            if row is not None and row[0]:
                return
            if row is not None:
                cursor.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {name}")
            cursor.execute("SELECT pg_table_size(%s::regclass)", [schema_editor.quote_name(model._meta.db_table)])
            small = cursor.fetchone()[0] <= self.plain_build_max_bytes
        if small and self._add_plainly(schema_editor, model, index):
            return
        with schema_editor.connection.cursor() as cursor:
            cursor.execute("SELECT set_config('lock_timeout', %s, false)", [self.concurrent_build_lock_timeout])
        try:
            schema_editor.add_index(model, index, concurrently=True)
        finally:
            with schema_editor.connection.cursor() as cursor:
                cursor.execute("RESET lock_timeout")

    def _wait_for_other_build(self, cursor, index_name):
        """Wait, at most concurrent_build_wait_seconds, for another backend's build of this index to end."""
        deadline = time.monotonic() + self.concurrent_build_wait_seconds
        while self._build_in_progress(cursor, index_name):
            if time.monotonic() >= deadline:
                msg = (
                    f"Another session has been building index {index_name} for over "
                    f"{self.concurrent_build_wait_seconds} s; run the migration again once it ends."
                )
                raise RuntimeError(msg)
            time.sleep(self.poll_seconds)

    def _add_plainly(self, schema_editor, model, index):
        """Build the index with a lock held for at most plain_build_lock_timeout; False if it could not be had."""
        try:
            with transaction.atomic(using=schema_editor.connection.alias):
                with schema_editor.connection.cursor() as cursor:
                    cursor.execute("SELECT set_config('lock_timeout', %s, true)", [self.plain_build_lock_timeout])
                schema_editor.add_index(model, index)
        except OperationalError as error:
            cause = error.__cause__
            # 55P03 lock_not_available: psycopg exposes SQLSTATE as sqlstate, psycopg2 as pgcode.
            if "55P03" not in {getattr(cause, "sqlstate", None), getattr(cause, "pgcode", None)}:
                raise
            return False
        return True

    @staticmethod
    def _build_in_progress(cursor, index_name):
        cursor.execute(
            "SELECT 1 FROM pg_stat_progress_create_index WHERE index_relid = to_regclass(%s) AND pid <> pg_backend_pid()",
            [index_name],
        )
        return cursor.fetchone() is not None


class Migration(migrations.Migration):

    """
    Index the event tables the way an object's history is read from them.

    pghistory reads an object's history by filtering every event table with a foreign key to the
    object's model on that key, and its copies of the keys carry no index, so every read scanned
    whole event tables. It then computes each event's diff from the object's previous event, which
    with only pgh_obj_id indexed read every event of the object once per event shown. On a large
    instance one finding's history page took minutes. Non-atomic so each index can build
    CONCURRENTLY; safe to re-run (see AddHistoryLookupIndexes).
    """

    atomic = False

    dependencies = [
        ("dojo", "0306_system_settings_read_only_mode"),
        ("pghistory", "0007_auto_20250421_0444"),
    ]

    operations = [
        AddHistoryLookupIndexes(
            indexes=[
                ("dojo_userevent", models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_dojo_u_pgh_obj_cf3c29_idx")),
                ("endpointevent", models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_endpoi_pgh_obj_a22c83_idx")),
                (
                    "endpointevent",
                    models.Index(
                        condition=models.Q(("product__isnull", False)),
                        fields=["product"],
                        name="dojo_endpointevt_product_hist",
                    ),
                ),
                ("endpointinheritedtagsevent", models.Index(fields=["endpoint"], name="dojo_endpointinhtags_hist")),
                ("endpointtagsevent", models.Index(fields=["endpoint"], name="dojo_endpointtags_hist")),
                ("engagementevent", models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_engage_pgh_obj_e92eff_idx")),
                ("engagementevent", models.Index(fields=["product"], name="dojo_engagementevt_prod_hist")),
                (
                    "engagementinheritedtagsevent",
                    models.Index(fields=["engagement"], name="dojo_engagementinhtags_hist"),
                ),
                ("engagementtagsevent", models.Index(fields=["engagement"], name="dojo_engagementtags_hist")),
                (
                    "finding_groupevent",
                    models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_findin_pgh_obj_9b4a6c_idx"),
                ),
                ("finding_groupevent", models.Index(fields=["test"], name="dojo_findinggroupevt_test_hist")),
                (
                    "finding_templateevent",
                    models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_findin_pgh_obj_24ee78_idx"),
                ),
                ("findingevent", models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_findin_pgh_obj_3fd2aa_idx")),
                ("findingevent", models.Index(fields=["test"], name="dojo_findingevt_test_hist")),
                (
                    "findingevent",
                    models.Index(
                        condition=models.Q(("duplicate_finding__isnull", False)),
                        fields=["duplicate_finding"],
                        name="dojo_findingevt_dupe_hist",
                    ),
                ),
                ("findinginheritedtagsevent", models.Index(fields=["finding"], name="dojo_findinginhtags_hist")),
                ("findingreviewersevent", models.Index(fields=["finding"], name="dojo_findingrevevt_find_hist")),
                ("findingtagsevent", models.Index(fields=["finding"], name="dojo_findingtags_hist")),
                (
                    "findingtemplatetagsevent",
                    models.Index(fields=["finding_template"], name="dojo_findingtemplatetags_hist"),
                ),
                ("locationevent", models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_locati_pgh_obj_46e7d8_idx")),
                (
                    "notification_webhooksevent",
                    models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_notifi_pgh_obj_b3d483_idx"),
                ),
                (
                    "product_typeevent",
                    models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_produc_pgh_obj_647f45_idx"),
                ),
                ("productevent", models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_produc_pgh_obj_282643_idx")),
                ("productevent", models.Index(fields=["prod_type"], name="dojo_productevt_prodtype_hist")),
                ("producttagsevent", models.Index(fields=["product"], name="dojo_producttags_hist")),
                (
                    "risk_acceptanceevent",
                    models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_risk_a_pgh_obj_5e9bdf_idx"),
                ),
                ("testevent", models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_testev_pgh_obj_5d7ff1_idx")),
                ("testevent", models.Index(fields=["engagement"], name="dojo_testevt_engagement_hist")),
                ("testevent", models.Index(fields=["test_type"], name="dojo_testevt_testtype_hist")),
                ("testinheritedtagsevent", models.Index(fields=["test"], name="dojo_testinhtags_hist")),
                ("testtagsevent", models.Index(fields=["test"], name="dojo_testtags_hist")),
                ("urlevent", models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_urleve_pgh_obj_91e795_idx")),
                ("urlevent", models.Index(fields=["location"], name="dojo_urlevt_location_hist")),
            ],
        ),
    ]
