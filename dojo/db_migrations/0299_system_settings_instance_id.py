import uuid

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dojo", "0298_risk_acceptance_restore_verified_expired"),
    ]

    operations = [
        migrations.AddField(
            model_name="system_settings",
            name="instance_id",
            field=models.UUIDField(
                default=uuid.uuid4,
                editable=False,
                help_text="Stable id of this DefectDojo instance. Exports use it to tell instances apart.",
                verbose_name="Instance ID",
            ),
        ),
    ]
