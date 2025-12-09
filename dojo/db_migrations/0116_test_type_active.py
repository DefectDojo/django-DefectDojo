
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0115_language_types'),
    ]

    operations = [
        migrations.AddField(
            model_name='test_type',
            name='active',
            field=models.BooleanField(default=True),
        ),
    ]
