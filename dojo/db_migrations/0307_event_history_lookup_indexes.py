import time

from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import OperationalError, migrations, models, transaction


class AddHistoryLookupIndex(AddIndexConcurrently):

    """
    Add an index to a pghistory event table without stopping event writes, safe to re-run.

    Event tables are written by triggers on every save of the tracked model, so an index build must
    not block them for long. A large table is built CONCURRENTLY. A small one (most of these hold a
    few hundred rows) is built plainly under a short lock_timeout: the build takes milliseconds,
    while CONCURRENTLY waits, twice, for every transaction in the database older than the build to
    end, which for dozens of tables behind a long-running import could take hours. When the plain
    build cannot get its lock in time, the concurrent build runs instead.

    A CONCURRENTLY build that was interrupted leaves an INVALID index of the same name. A re-run
    waits for such a build when it is still running elsewhere, then keeps a valid index or drops an
    invalid one and builds it again. Inside a caller's transaction (a test that migrates in a
    rolled-back transaction) the index is built plainly. Migration state is AddIndex's either way.
    """

    plain_build_max_bytes = 64 * 1024 * 1024
    plain_build_lock_timeout = "2s"
    poll_seconds = 5

    @staticmethod
    def _concurrent_allowed(schema_editor):
        connection = schema_editor.connection
        return connection.vendor == "postgresql" and not connection.in_atomic_block

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        if not self._concurrent_allowed(schema_editor):
            migrations.AddIndex(self.model_name, self.index).database_forwards(
                app_label, schema_editor, from_state, to_state,
            )
            return
        model = to_state.apps.get_model(app_label, self.model_name)
        if not self.allow_migrate_model(schema_editor.connection.alias, model):
            return
        name = schema_editor.quote_name(self.index.name)
        with schema_editor.connection.cursor() as cursor:
            while self._build_in_progress(cursor, name):
                time.sleep(self.poll_seconds)
            cursor.execute("SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass(%s)", [name])
            row = cursor.fetchone()
            if row is not None and row[0]:
                return
            if row is not None:
                cursor.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {name}")
            cursor.execute("SELECT pg_table_size(%s::regclass)", [schema_editor.quote_name(model._meta.db_table)])
            small = cursor.fetchone()[0] <= self.plain_build_max_bytes
        if small and self._add_plainly(schema_editor, model):
            return
        schema_editor.add_index(model, self.index, concurrently=True)

    def _add_plainly(self, schema_editor, model):
        """Build the index with a lock held for at most plain_build_lock_timeout; False if it could not be had."""
        try:
            with transaction.atomic(using=schema_editor.connection.alias):
                with schema_editor.connection.cursor() as cursor:
                    cursor.execute("SELECT set_config('lock_timeout', %s, true)", [self.plain_build_lock_timeout])
                schema_editor.add_index(model, self.index)
        except OperationalError as error:
            cause = error.__cause__
            # 55P03 lock_not_available: psycopg exposes SQLSTATE as sqlstate, psycopg2 as pgcode.
            if "55P03" not in {getattr(cause, "sqlstate", None), getattr(cause, "pgcode", None)}:
                raise
            return False
        return True

    @staticmethod
    def _build_in_progress(cursor, name):
        cursor.execute(
            "SELECT 1 FROM pg_stat_progress_create_index WHERE index_relid = to_regclass(%s) AND pid <> pg_backend_pid()",
            [name],
        )
        return cursor.fetchone() is not None

    def database_backwards(self, app_label, schema_editor, from_state, to_state):
        if self._concurrent_allowed(schema_editor):
            super().database_backwards(app_label, schema_editor, from_state, to_state)
            return
        migrations.AddIndex(self.model_name, self.index).database_backwards(
            app_label, schema_editor, from_state, to_state,
        )


class Migration(migrations.Migration):

    """
    Index the event tables the way an object's history is read from them.

    pghistory reads an object's history by filtering every event table with a foreign key to the
    object's model on that key, and its copies of the keys carry no index, so every read scanned
    whole event tables. It then computes each event's diff from the object's previous event, which
    with only pgh_obj_id indexed read every event of the object once per event shown. On a large
    instance one finding's history page took minutes. Non-atomic so each index can build
    CONCURRENTLY; safe to re-run (see AddHistoryLookupIndex).
    """

    atomic = False

    dependencies = [
        ("dojo", "0306_system_settings_read_only_mode"),
        ("pghistory", "0007_auto_20250421_0444"),
    ]

    operations = [
        AddHistoryLookupIndex(
            model_name="dojo_userevent",
            index=models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_dojo_u_pgh_obj_cf3c29_idx"),
        ),
        AddHistoryLookupIndex(
            model_name="endpointevent",
            index=models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_endpoi_pgh_obj_a22c83_idx"),
        ),
        AddHistoryLookupIndex(
            model_name="endpointevent",
            index=models.Index(condition=models.Q(("product__isnull", False)), fields=["product"], name="dojo_endpointevt_product_hist"),
        ),
        AddHistoryLookupIndex(
            model_name="endpointinheritedtagsevent",
            index=models.Index(fields=["endpoint"], name="dojo_endpointinhtags_hist"),
        ),
        AddHistoryLookupIndex(
            model_name="endpointtagsevent",
            index=models.Index(fields=["endpoint"], name="dojo_endpointtags_hist"),
        ),
        AddHistoryLookupIndex(
            model_name="engagementevent",
            index=models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_engage_pgh_obj_e92eff_idx"),
        ),
        AddHistoryLookupIndex(
            model_name="engagementevent",
            index=models.Index(fields=["product"], name="dojo_engagementevt_prod_hist"),
        ),
        AddHistoryLookupIndex(
            model_name="engagementinheritedtagsevent",
            index=models.Index(fields=["engagement"], name="dojo_engagementinhtags_hist"),
        ),
        AddHistoryLookupIndex(
            model_name="engagementtagsevent",
            index=models.Index(fields=["engagement"], name="dojo_engagementtags_hist"),
        ),
        AddHistoryLookupIndex(
            model_name="finding_groupevent",
            index=models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_findin_pgh_obj_9b4a6c_idx"),
        ),
        AddHistoryLookupIndex(
            model_name="finding_groupevent",
            index=models.Index(fields=["test"], name="dojo_findinggroupevt_test_hist"),
        ),
        AddHistoryLookupIndex(
            model_name="finding_templateevent",
            index=models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_findin_pgh_obj_24ee78_idx"),
        ),
        AddHistoryLookupIndex(
            model_name="findingevent",
            index=models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_findin_pgh_obj_3fd2aa_idx"),
        ),
        AddHistoryLookupIndex(
            model_name="findingevent",
            index=models.Index(fields=["test"], name="dojo_findingevt_test_hist"),
        ),
        AddHistoryLookupIndex(
            model_name="findingevent",
            index=models.Index(condition=models.Q(("duplicate_finding__isnull", False)), fields=["duplicate_finding"], name="dojo_findingevt_dupe_hist"),
        ),
        AddHistoryLookupIndex(
            model_name="findinginheritedtagsevent",
            index=models.Index(fields=["finding"], name="dojo_findinginhtags_hist"),
        ),
        AddHistoryLookupIndex(
            model_name="findingreviewersevent",
            index=models.Index(fields=["finding"], name="dojo_findingrevevt_find_hist"),
        ),
        AddHistoryLookupIndex(
            model_name="findingtagsevent",
            index=models.Index(fields=["finding"], name="dojo_findingtags_hist"),
        ),
        AddHistoryLookupIndex(
            model_name="findingtemplatetagsevent",
            index=models.Index(fields=["finding_template"], name="dojo_findingtemplatetags_hist"),
        ),
        AddHistoryLookupIndex(
            model_name="locationevent",
            index=models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_locati_pgh_obj_46e7d8_idx"),
        ),
        AddHistoryLookupIndex(
            model_name="notification_webhooksevent",
            index=models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_notifi_pgh_obj_b3d483_idx"),
        ),
        AddHistoryLookupIndex(
            model_name="product_typeevent",
            index=models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_produc_pgh_obj_647f45_idx"),
        ),
        AddHistoryLookupIndex(
            model_name="productevent",
            index=models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_produc_pgh_obj_282643_idx"),
        ),
        AddHistoryLookupIndex(
            model_name="productevent",
            index=models.Index(fields=["prod_type"], name="dojo_productevt_prodtype_hist"),
        ),
        AddHistoryLookupIndex(
            model_name="producttagsevent",
            index=models.Index(fields=["product"], name="dojo_producttags_hist"),
        ),
        AddHistoryLookupIndex(
            model_name="risk_acceptanceevent",
            index=models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_risk_a_pgh_obj_5e9bdf_idx"),
        ),
        AddHistoryLookupIndex(
            model_name="testevent",
            index=models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_testev_pgh_obj_5d7ff1_idx"),
        ),
        AddHistoryLookupIndex(
            model_name="testevent",
            index=models.Index(fields=["engagement"], name="dojo_testevt_engagement_hist"),
        ),
        AddHistoryLookupIndex(
            model_name="testevent",
            index=models.Index(fields=["test_type"], name="dojo_testevt_testtype_hist"),
        ),
        AddHistoryLookupIndex(
            model_name="testinheritedtagsevent",
            index=models.Index(fields=["test"], name="dojo_testinhtags_hist"),
        ),
        AddHistoryLookupIndex(
            model_name="testtagsevent",
            index=models.Index(fields=["test"], name="dojo_testtags_hist"),
        ),
        AddHistoryLookupIndex(
            model_name="urlevent",
            index=models.Index(fields=["pgh_obj", "pgh_id"], name="dojo_urleve_pgh_obj_91e795_idx"),
        ),
        AddHistoryLookupIndex(
            model_name="urlevent",
            index=models.Index(fields=["location"], name="dojo_urlevt_location_hist"),
        ),
    ]
