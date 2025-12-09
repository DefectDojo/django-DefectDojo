
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0122_cobaltio_product'),
    ]

    operations = [
        migrations.AddField(
            model_name='test',
            name='scan_type',
            field=models.TextField(null=True),
        ),
    ]
