from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    # CREATE INDEX CONCURRENTLY cannot run inside a transaction block, and avoids
    # an ACCESS EXCLUSIVE lock on the (large) dojo_finding table.
    atomic = False

    dependencies = [
        ("dojo", "0298_risk_acceptance_restore_verified_expired"),
    ]

    operations = [
        # Composite btree on (test, numerical_severity, id). Listing one test's
        # findings ordered by numerical_severity with a small LIMIT currently
        # sorts every finding in the test or walks the severity-only index and
        # filters by test. On tests with hundreds of thousands of findings this
        # lets the planner walk the index (forwards or backwards) and stop at the
        # LIMIT. The trailing id serves an id tiebreaker for stable pages.
        AddIndexConcurrently(
            model_name="finding",
            index=models.Index(
                fields=["test", "numerical_severity", "id"],
                name="idx_finding_test_numsev",
            ),
        ),
    ]
