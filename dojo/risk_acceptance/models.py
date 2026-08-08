from pathlib import Path

from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _

# copy_model_util is defined early in dojo.models, before the re-export that loads this
# module, so this resolves despite the partial circular load.
from dojo.models import copy_model_util


class Risk_Acceptance(models.Model):
    TREATMENT_ACCEPT = "A"
    TREATMENT_AVOID = "V"
    TREATMENT_MITIGATE = "M"
    TREATMENT_FIX = "F"
    TREATMENT_TRANSFER = "T"

    TREATMENT_TRANSLATIONS = {
        TREATMENT_ACCEPT: _("Accept (The risk is acknowledged, yet remains)"),
        TREATMENT_AVOID: _("Avoid (Do not engage with whatever creates the risk)"),
        TREATMENT_MITIGATE: _("Mitigate (The risk still exists, yet compensating controls make it less of a threat)"),
        TREATMENT_FIX: _("Fix (The risk is eradicated)"),
        TREATMENT_TRANSFER: _("Transfer (The risk is transferred to a 3rd party)"),
    }

    TREATMENT_CHOICES = [
        (TREATMENT_ACCEPT, TREATMENT_TRANSLATIONS[TREATMENT_ACCEPT]),
        (TREATMENT_AVOID, TREATMENT_TRANSLATIONS[TREATMENT_AVOID]),
        (TREATMENT_MITIGATE, TREATMENT_TRANSLATIONS[TREATMENT_MITIGATE]),
        (TREATMENT_FIX, TREATMENT_TRANSLATIONS[TREATMENT_FIX]),
        (TREATMENT_TRANSFER, TREATMENT_TRANSLATIONS[TREATMENT_TRANSFER]),
    ]

    name = models.CharField(max_length=300, null=False, blank=False, help_text=_("Descriptive name which in the future may also be used to group risk acceptances together across engagements and products"))

    accepted_findings = models.ManyToManyField("dojo.Finding")

    recommendation = models.CharField(choices=TREATMENT_CHOICES, max_length=2, null=False, default=TREATMENT_FIX, help_text=_("Recommendation from the security team."), verbose_name=_("Security Recommendation"))

    recommendation_details = models.TextField(null=True,
                                      blank=True,
                                      help_text=_("Explanation of security recommendation"), verbose_name=_("Security Recommendation Details"))

    decision = models.CharField(choices=TREATMENT_CHOICES, max_length=2, null=False, default=TREATMENT_ACCEPT, help_text=_("Risk treatment decision by risk owner"))
    decision_details = models.TextField(default=None, blank=True, null=True, help_text=_("If a compensating control exists to mitigate the finding or reduce risk, then list the compensating control(s)."))

    accepted_by = models.CharField(max_length=200, default=None, null=True, blank=True, verbose_name=_("Accepted By"), help_text=_("The person that accepts the risk, can be outside of DefectDojo."))
    path = models.FileField(upload_to="risk/%Y/%m/%d",
                            editable=True, null=True,
                            blank=True, verbose_name=_("Proof"))
    owner = models.ForeignKey("dojo.Dojo_User", editable=True, on_delete=models.RESTRICT, help_text=_("User in DefectDojo owning this acceptance. Only the owner and staff users can edit the risk acceptance."))

    expiration_date = models.DateTimeField(default=None, null=True, blank=True, help_text=_("When the risk acceptance expires, the findings will be reactivated (unless disabled below)."))
    expiration_date_warned = models.DateTimeField(default=None, null=True, blank=True, help_text=_("(readonly) Date at which notice about the risk acceptance expiration was sent."))
    expiration_date_handled = models.DateTimeField(default=None, null=True, blank=True, help_text=_("(readonly) When the risk acceptance expiration was handled (manually or by the daily job)."))
    reactivate_expired = models.BooleanField(null=False, blank=False, default=True, verbose_name=_("Reactivate findings on expiration"), help_text=_("Reactivate findings when risk acceptance expires?"))
    restart_sla_expired = models.BooleanField(default=False, null=False, verbose_name=_("Restart SLA on expiration"), help_text=_("When enabled, the SLA for findings is restarted when the risk acceptance expires."))

    notes = models.ManyToManyField("dojo.Notes", editable=False)
    created = models.DateTimeField(auto_now_add=True, null=False)
    updated = models.DateTimeField(auto_now=True, editable=False)

    def __str__(self):
        return str(self.name)

    def filename(self):
        # logger.debug('path: "%s"', self.path)
        if not self.path:
            return None
        return Path(self.path.name).name

    @property
    def name_and_expiration_info(self):
        return str(self.name) + (" (expired " if self.is_expired else " (expires ") + (timezone.localtime(self.expiration_date).strftime("%b %d, %Y") if self.expiration_date else "Never") + ")"

    def get_breadcrumbs(self):
        bc = self.engagement_set.first().get_breadcrumbs()
        bc += [{"title": str(self),
                "url": reverse("view_risk_acceptance", args=(
                    self.engagement_set.first().product.id, self.id))}]
        return bc

    @property
    def is_expired(self):
        return self.expiration_date_handled is not None

    # relationship is many to many, but we use it as one-to-many
    @property
    def engagement(self):
        engs = self.engagement_set.all()
        if engs:
            return engs[0]

        return None

    def copy(self, engagement=None):
        from dojo.models import Finding  # noqa: PLC0415 -- lazy import, avoids circular dependency
        copy = copy_model_util(self)
        # Save the necessary ManyToMany relationships
        old_notes = list(self.notes.all())
        old_accepted_findings_hash_codes = [finding.hash_code for finding in self.accepted_findings.all()]
        # Save the object before setting any ManyToMany relationships
        copy.save()
        # Copy the notes
        for notes in old_notes:
            copy.notes.add(notes.copy())
        # Assign any accepted findings
        if engagement:
            new_accepted_findings = Finding.objects.filter(test__engagement=engagement, hash_code__in=old_accepted_findings_hash_codes, risk_accepted=True).distinct()
            copy.accepted_findings.set(new_accepted_findings)
        return copy
