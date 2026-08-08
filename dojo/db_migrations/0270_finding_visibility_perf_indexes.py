from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    # CREATE INDEX CONCURRENTLY cannot run inside a transaction block, and avoids
    # an ACCESS EXCLUSIVE lock on the (large) dojo_finding table.
    atomic = False

    dependencies = [
        ("dojo", "0269_normalize_blank_finding_components"),
    ]

    operations = [
        AddIndexConcurrently(
            model_name="finding",
            index=models.Index(
                fields=["severity", "-numerical_severity"],
                name="idx_finding_sev_active",
                condition=models.Q(active=True),
            ),
        ),
        AddIndexConcurrently(
            model_name="finding",
            index=models.Index(
                fields=["-date"],
                name="idx_finding_riskaccepted_date",
                condition=models.Q(risk_accepted=True),
            ),
        ),
    ]
