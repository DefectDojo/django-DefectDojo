# Generated migration - Step 3: Finalize Risk_Acceptance move to Product

from django.db import migrations, models
import django.db.models.deletion
import pgtrigger


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0250_risk_acceptance_migrate_to_product'),
    ]

    operations = [
        migrations.AlterField(
            model_name='risk_acceptance',
            name='product',
            field=models.ForeignKey(editable=False, on_delete=django.db.models.deletion.CASCADE, related_name='risk_acceptances', to='dojo.product'),
        ),
        migrations.RemoveField(
            model_name='engagement',
            name='risk_acceptance',
        ),
    ]
