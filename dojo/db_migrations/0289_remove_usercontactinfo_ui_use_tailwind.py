from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0288_backfill_vulnerability_id_entities'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='usercontactinfo',
            name='ui_use_tailwind',
        ),
    ]
