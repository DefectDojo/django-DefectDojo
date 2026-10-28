from django.db import models
from django.utils.translation import gettext_lazy as _

class RiskAcceptanceEngagement(models.Model):
    STATUS_CHOICES = (
        ("Risks Active", "Risks Active"),
        ("Risks Reviewed", "Risks Reviewed"),
        ("Risks Pending", "Risks Pending"),
        ("Risks Accepted", "Risks Accepted"),
        ("Risks Rejected", "Risks Rejected"),
        ("Risks Expired", "Risks Expired"),
        )
    product = models.ForeignKey(
        "Product", null=True, blank=True, on_delete=models.CASCADE
    )
    description = models.TextField(blank=True, null=True)
    accepted_by = models.CharField(max_length=200, default=None, null=True, blank=True, verbose_name=_("Accepted By"), help_text=_("The person that accepts the risk, can be outside of DefectDojo."))
    reviewed_by = models.CharField(max_length=200, default=None, null=True, blank=True, verbose_name=_("Reviewed By"), help_text=_("The person that reviews the risk acceptance for acceptance long term"))
    reviewed_date = models.DateTimeField(default=None, null=True, blank=True, help_text=_("When the risk acceptance is reviewed"))
    accepted_date = models.DateTimeField(default=None, null=True, blank=True, help_text=_("When the risk acceptance is accepted"))
    expiration_date = models.DateTimeField(default=None, null=True, blank=True, help_text=_("When the risk acceptance expires, the findings will be reactivated (unless disabled below)."))
    cause = models.CharField(max_length=500, blank=True, null=True, verbose_name=_("Cause"), help_text=_("The cause of the long risk acceptance."))
    expiration_date_warned = models.DateTimeField(default=None, null=True, blank=True, help_text=_("(readonly) Date at which notice about the risk acceptance expiration was sent."))
    expiration_date_handled = models.DateTimeField(default=None, null=True, blank=True, help_text=_("(readonly) When the risk acceptance expiration was handled (manually or by the daily job)."))
    reactivate_expired = models.BooleanField(null=False, blank=False, default=True, verbose_name=_("Reactivate findings on expiration"), help_text=_("Reactivate findings when risk acceptance expires?"))
    risk_status = models.CharField(max_length=50, default="Risks Pending", choices=STATUS_CHOICES)
    risk_level = models.CharField(max_length=50, default="VERY CRITICAL", choices=(("TOLERABLE", "TOLERABLE"), ("MODERATE", "MODERATE"), ("CRITICAL", "CRITICAL"), ("VERY CRITICAL", "VERY CRITICAL")))
    owner = models.ForeignKey("Dojo_User", editable=True, null=True, on_delete=models.RESTRICT, help_text=_("User in DefectDojo owning this acceptance. Only the owner and staff users can edit the risk acceptance."))
    notes = models.ManyToManyField("Notes", editable=False)
    path = models.FileField(upload_to='long_risk_acceptance/%Y/%m/%d',
                        editable=True, null=True,
                        blank=True, verbose_name=('Proof'))
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    @property
    def economic_impact(self):
        if not self.pk:
            return 0

        sumary = 0
        for ec in self.riskacceptanceengagementeconomicimpact_set.all():
            if ec.economic_impact is not None:
                sumary += ec.economic_impact
        return sumary

    def save(self, *args, **kwargs):
        from dojo.models import GeneralSettings
        economic_impact = self.economic_impact
        rule_risk_level = GeneralSettings.get_value("RULE_RISK_LEVEL", {"TOLERABLE": 1500, "MODERATE": 2, "CRITICAL": 3700, "VERY CRITICAL": 8800})
        if economic_impact >= rule_risk_level["VERY CRITICAL"]:
            self.risk_level = "VERY CRITICAL"
        elif economic_impact >= rule_risk_level["CRITICAL"]:
            self.risk_level = "CRITICAL"
        elif economic_impact >= rule_risk_level["MODERATE"]:
            self.risk_level = "MODERATE"
        else:
            self.risk_level = "TOLERABLE"
        super().save(*args, **kwargs)

        
    def add_note(
        self,
        note_text,
        author,
        note_type=None,
        private=False):

        from dojo.models import Notes
        note = Notes.objects.create(
            entry=note_text,
            author=author,
            note_type=note_type,
            private=private,
        )

        self.notes.add(note)
        self.save()
        return note



class RiskAcceptanceExclusionRule(models.Model):
    TYPE_RULE_CHOICES = (
        ("CUSTOM", "CUSTOM"),
        ("BUSINESS", "BUSINESS"),
    )
    ra_engagement = models.ForeignKey(RiskAcceptanceEngagement, on_delete=models.CASCADE, null=True, blank=True)
    title = models.CharField(max_length=255, blank=True, null=True)
    filters = models.JSONField(blank=True, null=True)
    exclusions = models.JSONField(blank=True, null=True)
    type_rule =  models.CharField(choices=TYPE_RULE_CHOICES, default="CUSTOM")
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)


class RiskAcceptanceEngagementEconomicImpact(models.Model):
    title = models.CharField(max_length=255, blank=True, null=True, verbose_name=_("Title"), help_text=_("Title of the risk acceptance economic impact."))
    description = models.TextField(blank=True, null=True, verbose_name=_("Description"), help_text=_("Description of the risk acceptance economic impact."))
    control_effectiveness = models.IntegerField(null=True, blank=True, verbose_name=_("Control Effectiveness"), help_text=_("How effective is the control that mitigates the risk?"))
    economic_impact = models.IntegerField(null=True, blank=True, verbose_name=_("Economic Impact"), help_text=_("What is the economic impact of the risk?"))
    risk_acceptance_engagement = models.ForeignKey(RiskAcceptanceEngagement, on_delete=models.CASCADE, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)