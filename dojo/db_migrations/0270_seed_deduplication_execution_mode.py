from django.db import migrations


def seed_deduplication_execution_mode(apps, schema_editor):
    """
    Seed the new import deduplication execution mode from the legacy block_execution flag.

    block_execution remains the global "run all async tasks in the foreground" switch;
    users who had it enabled get the synchronous deduplication mode so import behavior is
    unchanged for them.
    """
    UserContactInfo = apps.get_model("dojo", "UserContactInfo")
    UserContactInfo.objects.filter(block_execution=True).update(deduplication_execution_mode="sync")


def unseed_deduplication_execution_mode(apps, schema_editor):
    """Reverse: clear the seeded synchronous mode."""
    UserContactInfo = apps.get_model("dojo", "UserContactInfo")
    UserContactInfo.objects.filter(deduplication_execution_mode="sync").update(deduplication_execution_mode=None)


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0269_usercontactinfo_deduplication_execution_mode'),
    ]

    operations = [
        migrations.RunPython(seed_deduplication_execution_mode, unseed_deduplication_execution_mode),
    ]
