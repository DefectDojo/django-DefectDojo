import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    """Schema only: create the Finding_CWE relationship (multiple CWEs per finding). The data
    backfill from the legacy Finding.cwe field is kept in a separate migration (0280) so data
    migrations are never mixed with schema migrations."""

    dependencies = [
        ("dojo", "0282_unique_finding_vulnerability_id"),
    ]

    operations = [
        migrations.CreateModel(
            name="Finding_CWE",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("cwe", models.CharField(db_index=True, max_length=11)),
                ("finding", models.ForeignKey(editable=False, on_delete=django.db.models.deletion.CASCADE, to="dojo.finding")),
            ],
        ),
        migrations.AddConstraint(
            model_name="finding_cwe",
            constraint=models.UniqueConstraint(fields=("finding", "cwe"), name="unique_finding_cwe"),
        ),
    ]
