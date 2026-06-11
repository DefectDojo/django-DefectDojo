from django.core.exceptions import ValidationError
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

    def save(self, *args, **kwargs):
        if self.pk:
            # Disallow editing of the infra type on an instance; engagement CICD FKs are scoped by infrastructure_type
            # via limit_choices_to (build_server/scm_server/orchestration), so changing the type would create a
            # semantic conflict between an engagement and this object.
            current_type = type(self).objects.filter(pk=self.pk).values_list("infrastructure_type", flat=True).first()
            if current_type is not None and current_type != self.infrastructure_type:
                raise ValidationError(
                    {"infrastructure_type": _("infrastructure_type cannot be changed once set.")},
                )
        super().save(*args, **kwargs)
