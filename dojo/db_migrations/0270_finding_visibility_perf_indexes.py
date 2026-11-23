import logging
import time

from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


logger = logging.getLogger(__name__)


class AddIndexConcurrentlyIfMissing(AddIndexConcurrently):

    """
    AddIndexConcurrently that can be re-run after a partial failure (copied from 0305).

    A CREATE INDEX CONCURRENTLY that is interrupted (the process is killed, the
    connection drops) leaves the index in the catalog marked INVALID, and a retry
    then fails with "relation ... already exists". Because this migration is not
    atomic, an earlier operation may also have finished before a later one failed.
    So: keep a valid index of the same name, drop an invalid leftover, then build.
    Migration state is unchanged from AddIndexConcurrently.

    Killing the migration process does not stop its build on the server, which
    runs on to completion. A build of this index that is still in progress is
    waited for first, so a retry keeps its result instead of dropping and
    rebuilding it.
    """

    poll_seconds = 5

    def database_forwards(self, app_label, schema_editor, from_state, to_state):
        self._ensure_not_in_transaction(schema_editor)
        model = to_state.apps.get_model(app_label, self.model_name)
        if not self.allow_migrate_model(schema_editor.connection.alias, model):
            return
        quoted_name = schema_editor.quote_name(self.index.name)
        with schema_editor.connection.cursor() as cursor:
            if self._build_in_progress(cursor, quoted_name):
                logger.warning("Waiting for an earlier build of index %s to finish", self.index.name)
                while self._build_in_progress(cursor, quoted_name):
                    time.sleep(self.poll_seconds)
                logger.warning("Earlier build of index %s finished", self.index.name)
            cursor.execute(
                "SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass(%s)",
                [quoted_name],
            )
            row = cursor.fetchone()
        if row is not None:
            if row[0]:
                return
            schema_editor.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {quoted_name}")
        schema_editor.add_index(model, self.index, concurrently=True)

    @staticmethod
    def _build_in_progress(cursor, quoted_name):
        cursor.execute(
            "SELECT 1 FROM pg_stat_progress_create_index"
            " WHERE index_relid = to_regclass(%s) AND pid <> pg_backend_pid()",
            [quoted_name],
        )
        return cursor.fetchone() is not None


class Migration(migrations.Migration):
    # CREATE INDEX CONCURRENTLY cannot run inside a transaction block, and avoids
    # an ACCESS EXCLUSIVE lock on the (large) dojo_finding table.
    atomic = False

    dependencies = [
        ("dojo", "0269_normalize_blank_finding_components"),
    ]

    operations = [
        AddIndexConcurrentlyIfMissing(
            model_name="finding",
            index=models.Index(
                fields=["severity", "-numerical_severity"],
                name="idx_finding_sev_active",
                condition=models.Q(active=True),
            ),
        ),
        AddIndexConcurrentlyIfMissing(
            model_name="finding",
            index=models.Index(
                fields=["-date"],
                name="idx_finding_riskaccepted_date",
                condition=models.Q(risk_accepted=True),
            ),
        ),
    ]
