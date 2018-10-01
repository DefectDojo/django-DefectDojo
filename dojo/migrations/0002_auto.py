from django.db import migrations, models

class Migration(migrations.Migration):

    initial = False
    dependencies = [
        ('dojo', '0001_initial')
    ]

    operations = [
        migrations.AddField(
            model_name='engagement',
            name='deduplication_level',
            field=models.CharField(max_length=10, default='product', choices=(
                (b'product', b'product'),
                (b'engagement', b'engagement')
                )
            )
        )
    ]
