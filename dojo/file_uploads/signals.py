from django.db.models.signals import post_delete, pre_save
from django.dispatch import receiver

from dojo.models import FileUpload


@receiver(post_delete, sender=FileUpload)
def delete_file_on_object_delete(sender, instance, **kwargs):
    """
    Deletes file from filesystem when corresponding `FileUpload` is deleted.
    Mostly used as a backup in case the FileUpload.delete() function fails
    for whatever reason
    """
    if instance.file:
        storage = instance.file.storage
        path = instance.file.path
        if path and storage.exists(path):
            storage.delete(path)


@receiver(pre_save, sender=FileUpload)
def delete_old_file_on_change(sender, instance, **kwargs):
    """Deletes old file when a new file is uploaded to the same record."""
    if not instance.pk:
        return  # Skip new objects
    try:
        old_file = FileUpload.objects.get(pk=instance.pk).file
    except FileUpload.DoesNotExist:
        return
    new_file = instance.file
    if old_file and old_file != new_file:
        storage = old_file.storage
        path = old_file.path
        if path and storage.exists(path):
            storage.delete(path)
