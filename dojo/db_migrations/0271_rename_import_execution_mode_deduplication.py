from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0270_remove_usercontactinfo_block_execution'),
    ]

    operations = [
        migrations.RenameField(
            model_name='usercontactinfo',
            old_name='import_execution_mode',
            new_name='deduplication_execution_mode',
        ),
    ]
