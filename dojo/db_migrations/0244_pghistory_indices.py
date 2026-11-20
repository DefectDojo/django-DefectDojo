# Generated manually for pghistory performance indexes

from django.db import migrations


def drop_index_if_invalid(schema_editor, name):
    """Drop index ``name`` when an interrupted concurrent build left it INVALID; return whether it did."""
    if schema_editor.connection.vendor != "postgresql":
        return False
    with schema_editor.connection.cursor() as cursor:
        # to_regclass resolves the name through search_path, as the CREATE does, and is NULL when there is none.
        cursor.execute("SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass(%s)", [name])
        row = cursor.fetchone()
        if row is None or row[0]:
            return False
        # The migration is non-atomic, so this runs in autocommit, which DROP INDEX CONCURRENTLY requires.
        cursor.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {schema_editor.quote_name(name)}")
        return True

INDEXES = (
    "pghistory_context_metadata_gin_idx",
    "pghistory_context_user_idx",
    "pghistory_context_remote_addr_idx",
    "pghistory_context_url_idx",
)


def drop_invalid_indexes(apps, schema_editor):  # noqa: ARG001 -- RunPython signature
    # An interrupted build leaves an INVALID index, which IF NOT EXISTS alone would keep
    # for good on the re-run. 0313 repairs databases that recorded one.
    for name in INDEXES:
        drop_index_if_invalid(schema_editor, name)


class Migration(migrations.Migration):
    # Mark as atomic=False to allow CONCURRENTLY operations
    atomic = False

    dependencies = [
        ('dojo', '0243_pghistory_models'),
    ]

    operations = [
        migrations.RunPython(drop_invalid_indexes, migrations.RunPython.noop),
        migrations.RunSQL(
            # Forward migration - add indexes with CONCURRENTLY to avoid table locks
            # Note: pghistory stores context as JSON in the 'metadata' column
            sql=[
                # GIN index on the entire JSON metadata field - supports general JSON queries
                # This is excellent for @>, ?, ?&, ?| operators and general JSON containment
                'CREATE INDEX CONCURRENTLY IF NOT EXISTS "pghistory_context_metadata_gin_idx" ON "pghistory_context" USING GIN ("metadata");',

                # Specific expression indexes for common filtering patterns
                # These complement the GIN index for exact value lookups

                # Index on user field from JSON - most selective for exact user filtering
                'CREATE INDEX CONCURRENTLY IF NOT EXISTS "pghistory_context_user_idx" ON "pghistory_context" ((metadata->>\'user\'));',

                # Index on remote_addr field from JSON - for IP address filtering (supports icontains)
                'CREATE INDEX CONCURRENTLY IF NOT EXISTS "pghistory_context_remote_addr_idx" ON "pghistory_context" ((metadata->>\'remote_addr\'));',

                # Index on url field from JSON - for URL filtering (helps with icontains queries)
                'CREATE INDEX CONCURRENTLY IF NOT EXISTS "pghistory_context_url_idx" ON "pghistory_context" ((metadata->>\'url\'));',
            ],
            # Reverse migration - drop indexes safely
            reverse_sql=[
                'DROP INDEX CONCURRENTLY IF EXISTS "pghistory_context_metadata_gin_idx";',
                'DROP INDEX CONCURRENTLY IF EXISTS "pghistory_context_user_idx";',
                'DROP INDEX CONCURRENTLY IF EXISTS "pghistory_context_remote_addr_idx";',
                'DROP INDEX CONCURRENTLY IF EXISTS "pghistory_context_url_idx";',
            ],
        ),
    ]

