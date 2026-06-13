from django.db import migrations


def block_execution_to_sync_mode(apps, schema_editor):
    """Map the legacy block_execution=True flag to the synchronous import execution mode."""
    UserContactInfo = apps.get_model("dojo", "UserContactInfo")
    UserContactInfo.objects.filter(block_execution=True).update(import_execution_mode="sync")


def sync_mode_to_block_execution(apps, schema_editor):
    """Reverse: restore block_execution=True for users on the synchronous mode."""
    UserContactInfo = apps.get_model("dojo", "UserContactInfo")
    UserContactInfo.objects.filter(import_execution_mode="sync").update(block_execution=True)


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0269_usercontactinfo_import_execution_mode'),
    ]

    operations = [
        migrations.RunPython(block_execution_to_sync_mode, sync_mode_to_block_execution),
        migrations.RemoveField(
            model_name='usercontactinfo',
            name='block_execution',
        ),
    ]
