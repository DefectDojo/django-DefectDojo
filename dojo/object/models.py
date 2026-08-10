from django.db import models
from django.utils.translation import gettext as _
from tagulous.models import TagField


class Objects_Review(models.Model):
    name = models.CharField(max_length=100, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True, null=False)

    def __str__(self):
        return self.name


class Objects_Product(models.Model):
    product = models.ForeignKey("dojo.Product", on_delete=models.CASCADE)
    name = models.CharField(max_length=100, null=True, blank=True)
    path = models.CharField(max_length=600, verbose_name=_("Full file path"),
                            null=True, blank=True)
    folder = models.CharField(max_length=400, verbose_name=_("Folder"),
                              null=True, blank=True)
    artifact = models.CharField(max_length=400, verbose_name=_("Artifact"),
                                null=True, blank=True)
    review_status = models.ForeignKey("dojo.Objects_Review", on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True, null=False)

    tags = TagField(blank=True, force_lowercase=True, help_text=_("Add tags that help describe this object. Choose from the list or add new tags. Press Enter key to add."))

    def __str__(self):
        name = None
        if self.path is not None:
            name = self.path
        elif self.folder is not None:
            name = self.folder
        elif self.artifact is not None:
            name = self.artifact

        return name
