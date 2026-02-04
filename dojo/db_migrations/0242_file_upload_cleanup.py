from django.db import migrations
from django.db.models import Q


def delete_unreferenced_file_uploads(apps, schema_editor):
    FileUpload = apps.get_model("dojo", "FileUpload")
    # Filter files that have no relations to Finding, Test, or Engagement
    unused_files = FileUpload.objects.filter(
        Q(finding__isnull=True) &
        Q(test__isnull=True) &
        Q(engagement__isnull=True)
    ).distinct()
    # Delete the files from disk first, then delete the FileUpload object
    for file_upload in unused_files:
        if file_upload.file:
            storage = file_upload.file.storage
            path = file_upload.file.path
            if path and storage.exists(path):
                storage.delete(path)
        file_upload.delete()


def cannot_turn_back_time(apps, schema_editor):
    """
    We cannot possibly return to the original state without knowing
    the original value at the time the migration is revoked. Instead
    we will do nothing.
    """
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("dojo", "0241_remove_system_settings_time_zone"), 
    ]

    operations = [
        migrations.RunPython(delete_unreferenced_file_uploads, cannot_turn_back_time),
    ]