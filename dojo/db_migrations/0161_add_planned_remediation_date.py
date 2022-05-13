from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0160_set_notnull_endpoint_statuses')
    ]

    operations = [
        migrations.AddField(
            model_name='finding',
            name='planned_remediation_date',
            field=models.DateField(
                null=True,
                blank=True,
                verbose_name="Planned Remediation Date",
                help_text="Date when this Findings is expected to be remediated.",
            ),
        ),
    ]
