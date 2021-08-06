from django.core.management import call_command
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0109_group_user_role'),
    ]

    def migrate_users(apps, schema_editor):
        call_command('migrate_authorization_v2')

    operations = [
        # Migrate roles for staff users and authorized users to authorization v2
        migrations.RunPython(migrate_users),
    ]
