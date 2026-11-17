"""
Drop the foreign keys of the tables that removed features left behind.

0265_remove_stub_finding and 0266_remove_credential_manager removed Stub_Finding and the
Credential Manager models from Django's state only. Their tables stayed, and so did their
DEFERRABLE INITIALLY DEFERRED foreign keys into live tables (dojo_product, dojo_engagement,
dojo_test, dojo_finding, dojo_development_environment, dojo_notes, auth_user). No model
declares those tables any more, so no delete clears their rows, and deleting an object one of
those rows still references failed when its transaction committed.

This drops every foreign key the five tables own and nothing else: the tables, their rows and
their triggers stay. The constraints are looked up in the catalog rather than named, so an
install with other constraint names, or without one of the tables, migrates the same way, and
a re-run finds nothing left to drop. The state is unchanged (it lost these tables in 0265 and
0266).

Dropping a foreign key reads no rows, but it takes an ACCESS EXCLUSIVE lock on the referenced
table too (dojo_finding, dojo_test, ...). So the migration is not atomic: each constraint is
dropped in its own transaction, which holds one such lock for a few milliseconds, under a short
lock timeout. A drop that cannot get its lock in time is retried a few times rather than left
queued behind a long transaction, stalling every query that would queue behind it.

There is no reverse: the constraints cannot be put back once rows they would reject exist.
"""

import logging
import time

from django.db import OperationalError, migrations, transaction

logger = logging.getLogger(__name__)

LEGACY_TABLES = (
    "dojo_cred_mapping",
    "dojo_cred_user",
    "dojo_cred_user_notes",
    "dojo_cred_userevent",
    "dojo_stub_finding",
)

LOCK_TIMEOUT = "5s"
ATTEMPTS = 5
RETRY_SECONDS = 5
LOCK_NOT_AVAILABLE = "55P03"


def legacy_foreign_keys(cursor):
    """Every foreign key a legacy table owns, as (table, constraint); a missing table has none."""
    cursor.execute(
        "SELECT c.conrelid::regclass::text, c.conname FROM pg_constraint c"
        " WHERE c.contype = 'f' AND c.conrelid IN"
        " (SELECT to_regclass(t) FROM unnest(%s::text[]) t)"
        " ORDER BY 1, 2",
        [list(LEGACY_TABLES)],
    )
    return cursor.fetchall()


def drop_foreign_key(connection, table, constraint):
    for attempt in range(1, ATTEMPTS + 1):
        try:
            with transaction.atomic(using=connection.alias), connection.cursor() as cursor:
                cursor.execute("SELECT set_config('lock_timeout', %s, true)", [LOCK_TIMEOUT])
                # table comes from regclass::text, which quotes it when it needs quoting.
                cursor.execute(
                    f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {connection.ops.quote_name(constraint)}",
                )
        except OperationalError as error:
            if getattr(error.__cause__, "sqlstate", None) != LOCK_NOT_AVAILABLE:
                raise
            if attempt == ATTEMPTS:
                msg = (
                    f"Could not drop the foreign key {constraint} on {table}: another transaction kept a lock on a "
                    f"table it references through {ATTEMPTS} attempts of {LOCK_TIMEOUT} each. Run migrate again "
                    "when fewer imports, deletes or reports are running. A re-run is safe: it drops only the "
                    "foreign keys still left and picks up where this run stopped."
                )
                raise OperationalError(msg) from error
            logger.warning(
                "Could not lock the tables to drop %s on %s (attempt %d of %d), retrying",
                constraint, table, attempt, ATTEMPTS,
            )
            time.sleep(RETRY_SECONDS)
        else:
            return


def drop_legacy_foreign_keys(apps, schema_editor):
    connection = schema_editor.connection
    if connection.vendor != "postgresql":
        return
    with connection.cursor() as cursor:
        constraints = legacy_foreign_keys(cursor)
    for table, constraint in constraints:
        drop_foreign_key(connection, table, constraint)


class Migration(migrations.Migration):

    atomic = False

    dependencies = [
        ("dojo", "0309_jira_project_suppress_sla_notification_comments"),
    ]

    operations = [
        migrations.RunPython(drop_legacy_foreign_keys, migrations.RunPython.noop),
    ]
