from django.db import models
from django.utils.translation import gettext as _


class Regulation(models.Model):
    PRIVACY_CATEGORY = "privacy"
    FINANCE_CATEGORY = "finance"
    EDUCATION_CATEGORY = "education"
    MEDICAL_CATEGORY = "medical"
    CORPORATE_CATEGORY = "corporate"
    SECURITY_CATEGORY = "security"
    GOVERNMENT_CATEGORY = "government"
    OTHER_CATEGORY = "other"
    CATEGORY_CHOICES = (
        (PRIVACY_CATEGORY, _("Privacy")),
        (FINANCE_CATEGORY, _("Finance")),
        (EDUCATION_CATEGORY, _("Education")),
        (MEDICAL_CATEGORY, _("Medical")),
        (CORPORATE_CATEGORY, _("Corporate")),
        (SECURITY_CATEGORY, _("Security")),
        (GOVERNMENT_CATEGORY, _("Government")),
        (OTHER_CATEGORY, _("Other")),
    )

    name = models.CharField(max_length=128, unique=True, help_text=_("The name of the regulation."))
    acronym = models.CharField(max_length=20, unique=True, help_text=_("A shortened representation of the name."))
    category = models.CharField(max_length=16, choices=CATEGORY_CHOICES, help_text=_("The subject of the regulation."))
    jurisdiction = models.CharField(max_length=64, help_text=_("The territory over which the regulation applies."))
    description = models.TextField(blank=True, help_text=_("Information about the regulation's purpose."))
    reference = models.URLField(blank=True, help_text=_("An external URL for more information."))

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.acronym + " (" + self.jurisdiction + ")"
