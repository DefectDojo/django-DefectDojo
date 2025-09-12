# Generated manually for pghistory performance indexes

from django.db import migrations


class Migration(migrations.Migration):
    # Mark as atomic=False to allow CONCURRENTLY operations
    atomic = False

    dependencies = [
        ('dojo', '0243_pghistory_models'),
    ]

    operations = [
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

