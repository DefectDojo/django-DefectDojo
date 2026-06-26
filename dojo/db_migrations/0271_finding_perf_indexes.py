from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    # CREATE INDEX CONCURRENTLY cannot run inside a transaction block, and avoids
    # an ACCESS EXCLUSIVE lock on the (large) dojo_finding table.
    atomic = False

    dependencies = [
        ("dojo", "0270_finding_visibility_perf_indexes"),
    ]

    operations = [
        AddIndexConcurrently(
            model_name="finding",
            index=models.Index(
                fields=["test", "date"],
                name="idx_finding_testid_date",
            ),
        ),
        AddIndexConcurrently(
            model_name="finding",
            index=models.Index(
                fields=["sla_expiration_date", "test"],
                name="idx_finding_sla_open_cov",
                condition=models.Q(is_mitigated=False),
            ),
        ),
        AddIndexConcurrently(
            model_name="finding",
            index=models.Index(
                fields=["severity"],
                name="idx_finding_open_active_sev",
                condition=models.Q(active=True, is_mitigated=False),
            ),
        ),
        AddIndexConcurrently(
            model_name="finding",
            index=models.Index(
                fields=["severity", "-numerical_severity"],
                name="idx_finding_sev_open_unver",
                condition=models.Q(active=True, verified=False),
            ),
        ),
        AddIndexConcurrently(
            model_name="finding",
            index=models.Index(
                fields=["test", "sla_expiration_date", "date"],
                name="idx_finding_sla_breach_cov",
                include=["id"],
                condition=models.Q(is_mitigated=False),
            ),
        ),
    ]
