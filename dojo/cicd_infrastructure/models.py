from django.db import models
from django.utils.translation import gettext as _


class CICDInfrastructure(models.Model):
    INFRASTRUCTURE_TYPE_CHOICES = (
        ("build_server", "Build Server"),
        ("scm_server", "SCM Server"),
        ("orchestration", "Orchestration Engine"),
    )

    name = models.CharField(max_length=200)
    description = models.CharField(max_length=2000, blank=True, default="")
    url = models.URLField(max_length=2000, blank=True, default="", help_text=_("Public URL of the tool (e.g., https://jenkins.company.com)"))
    infrastructure_type = models.CharField(max_length=30, choices=INFRASTRUCTURE_TYPE_CHOICES)

    class Meta:
        ordering = ["name"]
        unique_together = [("name", "infrastructure_type")]

    def __str__(self):
        return self.name
