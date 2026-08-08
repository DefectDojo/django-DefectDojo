from pathlib import Path
from uuid import uuid4

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.db import models
from django.utils.translation import gettext_lazy as _

from dojo.models import (  # UniqueUploadNameProvider kept in dojo.models for migration upload_to path stability
    UniqueUploadNameProvider,
    copy_model_util,
)


class FileUpload(models.Model):
    title = models.CharField(max_length=100, unique=True)
    file = models.FileField(upload_to=UniqueUploadNameProvider("uploaded_files"))

    def delete(self, *args, **kwargs):
        """Delete the model and remove the file from storage."""
        storage = self.file.storage
        path = self.file.path
        super().delete(*args, **kwargs)
        if path and storage.exists(path):
            storage.delete(path)

    def copy(self):
        copy = copy_model_util(self)
        # Add unique modifier to file name
        # Truncate title to ensure it doesn't exceed max_length (100) when appending suffix
        # Suffix " - clone-{8 chars}" is 17 characters, so truncate to 83 chars
        clone_suffix = f" - clone-{str(uuid4())[:8]}"
        max_title_length = 100 - len(clone_suffix)
        truncated_title = self.title[:max_title_length] if len(self.title) > max_title_length else self.title
        copy.title = f"{truncated_title}{clone_suffix}"
        # Create new unique file name
        current_url = self.file.url
        _, current_full_filename = current_url.rsplit("/", 1)
        _, extension = current_full_filename.split(".", 1)
        new_file = ContentFile(self.file.read(), name=f"{uuid4()}.{extension}")
        copy.file = new_file
        copy.save()

        return copy

    def get_accessible_url(self, obj, obj_id):
        from dojo.engagement.models import Engagement  # noqa: PLC0415 -- lazy import, avoids circular dependency
        from dojo.finding.models import Finding  # noqa: PLC0415 -- lazy import, avoids circular dependency
        from dojo.test.models import Test  # noqa: PLC0415 -- lazy import, avoids circular dependency
        if isinstance(obj, Engagement):
            obj_type = "Engagement"
        elif isinstance(obj, Test):
            obj_type = "Test"
        elif isinstance(obj, Finding):
            obj_type = "Finding"

        return f"access_file/{self.id}/{obj_id}/{obj_type}"

    def clean(self):
        if not self.title:
            self.title = "<No Title>"

        valid_extensions = settings.FILE_UPLOAD_TYPES

        # why does this not work with self.file....
        file_name = self.file.url if self.file else self.title
        if Path(file_name).suffix.lower() not in valid_extensions:
            if accepted_extensions := f"{', '.join(valid_extensions)}":
                msg = (
                    _("Unsupported extension. Supported extensions are as follows: %s") % accepted_extensions
                )
            else:
                msg = (
                    _("File uploads are prohibited due to the list of acceptable file extensions being empty")
                )
            raise ValidationError(msg)


class FileAccessToken(models.Model):

    """
    This will allow reports to request the images without exposing the
    media root to the world without
    authentication
    """

    user = models.ForeignKey("dojo.Dojo_User", null=False, blank=False, on_delete=models.CASCADE)
    file = models.ForeignKey("dojo.FileUpload", null=False, blank=False, on_delete=models.CASCADE)
    token = models.CharField(max_length=255)
    size = models.CharField(max_length=9,
                            choices=(
                                ("small", "Small"),
                                ("medium", "Medium"),
                                ("large", "Large"),
                                ("thumbnail", "Thumbnail"),
                                ("original", "Original")),
                            default="medium")

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = uuid4()
        return super().save(*args, **kwargs)
