from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    operations = [
        migrations.AddField(
            model_name='finding',
            name='estimated_remediation_date',
            field=models.DateField(
                null=True,
                blank=True,
                verbose_name="Estimated Remediation Date",
                help_text="Date when this Findings is expected to be remediated.",
            ),
        ),
    ]
