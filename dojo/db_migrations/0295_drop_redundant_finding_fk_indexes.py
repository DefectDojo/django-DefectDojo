"""Drop two `dojo_finding` indexes that a wider index already covers.

Django creates a single-column index for every ForeignKey. On `Finding` two of those are
redundant, because another index already begins with the same column:

    (test_id)               -> covered by nine composites that lead with test_id, e.g.
                               (test_id, active, verified), (test_id, hash_code, duplicate)
    (duplicate_finding_id)  -> covered by (duplicate_finding_id, id)

A btree whose columns are a strict prefix of another btree, with the same (here, absent)
partial predicate, can be answered from the longer index, so the shorter one returns
nothing for the write cost it adds to every finding insert. `dojo_finding` is the busiest
table in the schema and carries close to fifty indexes, so each one removed is a real
saving on import.

Dropping the referencing-side index does not weaken the foreign keys. PostgreSQL requires
an index on the REFERENCED (unique) side of a foreign key, not on the referencing side; the
referencing-side index only accelerates cascade deletes and parent-row deletion checks, and
in both cases a covering composite remains.

Built with DROP INDEX CONCURRENTLY (non-atomic migration, following 0280) so it does not
take an exclusive lock on a large `dojo_finding`. IF EXISTS makes it idempotent, and the
reverse rebuilds concurrently too, so a downgrade does not lock the table either.

The index names are Django's deterministic auto-generated names for these two foreign keys
(table + column + a hash of both), so they are identical on every install.
"""
from django.db import migrations, models


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("dojo", "0294_usercontactinfo_language"),
    ]

    operations = [
        # RunSQL does the concurrent DB work; state_operations keeps Django's model state in
        # step with db_index=False on the fields, so a later makemigrations stays a no-op.
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunSQL(
                    sql="DROP INDEX CONCURRENTLY IF EXISTS dojo_finding_test_id_ef8ec5fc",
                    reverse_sql=(
                        "CREATE INDEX CONCURRENTLY IF NOT EXISTS dojo_finding_test_id_ef8ec5fc "
                        "ON dojo_finding (test_id)"
                    ),
                ),
                migrations.RunSQL(
                    sql="DROP INDEX CONCURRENTLY IF EXISTS dojo_finding_duplicate_finding_id_9ff391c5",
                    reverse_sql=(
                        "CREATE INDEX CONCURRENTLY IF NOT EXISTS "
                        "dojo_finding_duplicate_finding_id_9ff391c5 ON dojo_finding (duplicate_finding_id)"
                    ),
                ),
            ],
            state_operations=[
                migrations.AlterField(
                    model_name="finding",
                    name="test",
                    field=models.ForeignKey(
                        db_index=False,
                        editable=False,
                        help_text="The test that is associated with this flaw.",
                        on_delete=models.CASCADE,
                        to="dojo.test",
                        verbose_name="Test",
                    ),
                ),
                migrations.AlterField(
                    model_name="finding",
                    name="duplicate_finding",
                    field=models.ForeignKey(
                        blank=True,
                        db_index=False,
                        editable=False,
                        help_text="Link to the original finding if this finding is a duplicate.",
                        null=True,
                        on_delete=models.DO_NOTHING,
                        related_name="original_finding",
                        to="dojo.finding",
                        verbose_name="Duplicate Finding",
                    ),
                ),
            ],
        ),
    ]
