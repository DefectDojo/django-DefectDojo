from django.db import migrations

# The builds of 0244 and 0280, restated as literals: a migration must not import another's code.
CONCURRENT_INDEXES = {
    "pghistory_context_metadata_gin_idx": 'CREATE INDEX CONCURRENTLY IF NOT EXISTS "pghistory_context_metadata_gin_idx" ON "pghistory_context" USING GIN ("metadata")',
    "pghistory_context_user_idx": 'CREATE INDEX CONCURRENTLY IF NOT EXISTS "pghistory_context_user_idx" ON "pghistory_context" ((metadata->>\'user\'))',
    "pghistory_context_remote_addr_idx": 'CREATE INDEX CONCURRENTLY IF NOT EXISTS "pghistory_context_remote_addr_idx" ON "pghistory_context" ((metadata->>\'remote_addr\'))',
    "pghistory_context_url_idx": 'CREATE INDEX CONCURRENTLY IF NOT EXISTS "pghistory_context_url_idx" ON "pghistory_context" ((metadata->>\'url\'))',
    "dojo_vulnid_upper_idx": (
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS dojo_vulnid_upper_idx "
        "ON dojo_vulnerability_id (UPPER(vulnerability_id), finding_id)"
    ),
}


def repair_invalid_indexes(apps, schema_editor):  # noqa: ARG001 -- RunPython signature
    """Drop each index that is INVALID, then build each one that is missing. A valid index is kept."""
    if schema_editor.connection.vendor != "postgresql":
        return
    with schema_editor.connection.cursor() as cursor:
        for name, create_sql in CONCURRENT_INDEXES.items():
            cursor.execute("SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass(%s)", [name])
            row = cursor.fetchone()
            if row is not None and row[0]:
                continue
            if row is not None:
                # Non-atomic migration, so autocommit, which both CONCURRENTLY statements require.
                cursor.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {schema_editor.quote_name(name)}")
            cursor.execute(create_sql)


class Migration(migrations.Migration):

    """
    Rebuild an index of 0244 or 0280 where a database recorded it INVALID.

    Before 0244 and 0280 dropped an INVALID leftover, a re-run after an interrupted
    CREATE INDEX CONCURRENTLY met the leftover, skipped the build (IF NOT EXISTS) and
    recorded the migration, so the planner never used the index and nothing reported why.
    Editing those migrations does not reach such databases, so this drops each index when
    it is INVALID and builds it when it is missing. A valid index is kept, and a database
    that applied them cleanly sees no change. No state change.

    indisvalid is also false for a build still running on the server; dropping it waits
    for that build and then builds again, so a very large table can be indexed twice.
    """

    atomic = False

    dependencies = [
        ("dojo", "0312_alerts_bigint_id"),
    ]

    operations = [
        migrations.RunPython(repair_invalid_indexes, migrations.RunPython.noop),
    ]
