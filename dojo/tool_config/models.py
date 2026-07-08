from django.db import models
from django.utils.translation import gettext_lazy as _


class Tool_Configuration(models.Model):
    name = models.CharField(max_length=200, null=False)
    description = models.CharField(max_length=2000, null=True, blank=True)
    url = models.CharField(max_length=2000, null=True, blank=True)
    tool_type = models.ForeignKey("dojo.Tool_Type", related_name="tool_type", on_delete=models.CASCADE)
    authentication_type = models.CharField(max_length=15,
                                           choices=(
                                               ("API", "API Key"),
                                               ("Password",
                                                "Username/Password"),
                                               ("SSH", "SSH")),
                                           null=True, blank=True)
    extras = models.CharField(max_length=255, null=True, blank=True, help_text=_("Additional definitions that will be "
                                                                             "consumed by scanner"))
    username = models.CharField(max_length=200, null=True, blank=True)
    password = models.CharField(max_length=900, null=True, blank=True)
    auth_title = models.CharField(max_length=200, null=True, blank=True,
                                  verbose_name=_("Title for SSH/API Key"))
    ssh = models.CharField(max_length=9000, null=True, blank=True)
    api_key = models.CharField(max_length=900, null=True, blank=True,
                               verbose_name=_("API Key"))

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name
