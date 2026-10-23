from django.db import models
from django.utils.timezone import now
from django.utils.translation import gettext_lazy as _

from dojo.query_hooks import HookedManager, UnfilteredManager


class Tool_Product_Settings(models.Model):
    name = models.CharField(max_length=200, null=False)
    description = models.CharField(max_length=2000, null=True, blank=True)
    url = models.CharField(max_length=2000, null=True, blank=True)
    product = models.ForeignKey("dojo.Product", default=1, editable=False, on_delete=models.CASCADE)
    tool_configuration = models.ForeignKey("dojo.Tool_Configuration", null=False,
                                           related_name="tool_configuration", on_delete=models.CASCADE)
    tool_project_id = models.CharField(max_length=200, null=True, blank=True)
    notes = models.ManyToManyField("dojo.Notes", blank=True, editable=False)

    # Read and written only by plugins; open source never sets them.
    archived_at = models.DateTimeField(null=True, blank=True, editable=False)
    archive_batch = models.UUIDField(null=True, blank=True, editable=False)

    # objects is declared first, so it is the default manager; see dojo.query_hooks.
    objects = HookedManager()
    unfiltered = UnfilteredManager()

    class Meta:
        ordering = ["name"]


class Tool_Product_History(models.Model):
    product = models.ForeignKey("dojo.Tool_Product_Settings", editable=False, on_delete=models.CASCADE)
    last_scan = models.DateTimeField(null=False, editable=False, default=now)
    succesfull = models.BooleanField(default=True, verbose_name=_("Succesfully"))
    configuration_details = models.CharField(max_length=2000, null=True,
                                             blank=True)
