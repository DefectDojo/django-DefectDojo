
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0114_cyclonedx_vuln_uniqu'),
    ]

    operations = [
        migrations.AddField(
            model_name='test_type',
            name='active',
            field=models.BooleanField(default=True),
        ),
    ]
