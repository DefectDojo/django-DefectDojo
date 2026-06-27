import logging
from contextlib import suppress

from dateutil.relativedelta import relativedelta
from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _
from tagulous.models import TagField

from dojo.base_models.base import BaseModel

logger = logging.getLogger(__name__)


class Engagement_Presets(models.Model):
    title = models.CharField(max_length=500, default=None, help_text=_("Brief description of preset."))
    test_type = models.ManyToManyField("dojo.Test_Type", default=None, blank=True)
    network_locations = models.ManyToManyField("dojo.Network_Locations", default=None, blank=True)
    notes = models.CharField(max_length=2000, help_text=_("Description of what needs to be tested or setting up environment for testing"), null=True, blank=True)
    scope = models.CharField(max_length=800, help_text=_("Scope of Engagement testing, IP's/Resources/URL's)"), default=None, blank=True)
    product = models.ForeignKey("dojo.Product", on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True, null=False)

    class Meta:
        ordering = ["title"]

    def __str__(self):
        return self.title


ENGAGEMENT_STATUS_CHOICES = (("Not Started", "Not Started"),
                             ("Blocked", "Blocked"),
                             ("Cancelled", "Cancelled"),
                             ("Completed", "Completed"),
                             ("In Progress", "In Progress"),
                             ("On Hold", "On Hold"),
                             ("Scheduled", "Scheduled"),
                             ("Waiting for Resource", "Waiting for Resource"))


class Engagement(BaseModel):
    name = models.CharField(max_length=300, null=True, blank=True)
    description = models.CharField(max_length=2000, null=True, blank=True)
    version = models.CharField(max_length=100, null=True, blank=True, help_text=_("Version of the product the engagement tested."))
    first_contacted = models.DateField(null=True, blank=True)
    target_start = models.DateField(null=False, blank=False)
    target_end = models.DateField(null=False, blank=False)
    lead = models.ForeignKey("dojo.Dojo_User", editable=True, null=True, blank=True, on_delete=models.RESTRICT)
    requester = models.ForeignKey("dojo.Contact", null=True, blank=True, on_delete=models.CASCADE)
    preset = models.ForeignKey("dojo.Engagement_Presets", null=True, blank=True, help_text=_("Settings and notes for performing this engagement."), on_delete=models.CASCADE)
    reason = models.CharField(max_length=2000, null=True, blank=True)
    report_type = models.ForeignKey("dojo.Report_Type", null=True, blank=True, on_delete=models.CASCADE)
    product = models.ForeignKey("dojo.Product", on_delete=models.CASCADE)
    active = models.BooleanField(default=True, editable=False)
    tracker = models.URLField(max_length=200, help_text=_("Link to epic or ticket system with changes to version."), editable=True, blank=True, null=True)
    test_strategy = models.URLField(editable=True, blank=True, null=True)
    threat_model = models.BooleanField(default=True)
    api_test = models.BooleanField(default=True)
    pen_test = models.BooleanField(default=True)
    check_list = models.BooleanField(default=True)
    notes = models.ManyToManyField("dojo.Notes", blank=True, editable=False)
    files = models.ManyToManyField("dojo.FileUpload", blank=True, editable=False)
    status = models.CharField(editable=True, max_length=2000, default="Not Started",
                              null=True,
                              choices=ENGAGEMENT_STATUS_CHOICES)
    progress = models.CharField(max_length=100,
                                default="threat_model", editable=False)
    tmodel_path = models.CharField(max_length=1000, default="none",
                                   editable=False, blank=True, null=True)
    risk_acceptance = models.ManyToManyField("dojo.Risk_Acceptance",
                                             default=None,
                                             editable=False,
                                             blank=True)
    done_testing = models.BooleanField(default=False, editable=False)
    engagement_type = models.CharField(editable=True, max_length=30, default="Interactive",
                                       null=True,
                                       choices=(("Interactive", "Interactive"),
                                                ("CI/CD", "CI/CD")))
    build_id = models.CharField(editable=True, max_length=150,
                                   null=True, blank=True, help_text=_("Build ID of the product the engagement tested."), verbose_name=_("Build ID"))
    commit_hash = models.CharField(editable=True, max_length=150,
                                   null=True, blank=True, help_text=_("Commit hash from repo"), verbose_name=_("Commit Hash"))
    branch_tag = models.CharField(editable=True, max_length=150,
                                   null=True, blank=True, help_text=_("Tag or branch of the product the engagement tested."), verbose_name=_("Branch/Tag"))
    source_code_management_uri = models.URLField(max_length=600, null=True, blank=True, editable=True, verbose_name=_("Repo"), help_text=_("Resource link to source code"))
    cicd_scm_server = models.ForeignKey("dojo.CICDInfrastructure", null=True, blank=True, related_name="engagements_as_scm_server", on_delete=models.SET_NULL, limit_choices_to={"infrastructure_type": "scm_server"}, verbose_name=_("SCM Server"), help_text=_("Source code management server used for this CI/CD engagement"))
    cicd_build_server = models.ForeignKey("dojo.CICDInfrastructure", null=True, blank=True, related_name="engagements_as_build_server", on_delete=models.SET_NULL, limit_choices_to={"infrastructure_type": "build_server"}, verbose_name=_("Build Server"), help_text=_("Build server used for this CI/CD engagement"))
    cicd_orchestration_engine = models.ForeignKey("dojo.CICDInfrastructure", null=True, blank=True, related_name="engagements_as_orchestration", on_delete=models.SET_NULL, limit_choices_to={"infrastructure_type": "orchestration"}, verbose_name=_("Orchestration Engine"), help_text=_("Orchestration engine used for this CI/CD engagement"))
    deduplication_on_engagement = models.BooleanField(default=False, verbose_name=_("Deduplication within this engagement only"), help_text=_("If enabled deduplication will only mark a finding in this engagement as duplicate of another finding if both findings are in this engagement. If disabled, deduplication is on the product level."))

    tags = TagField(blank=True, force_lowercase=True, help_text=_("Add tags that help describe this engagement. Choose from the list or add new tags. Press Enter key to add."))
    inherited_tags = TagField(blank=True, force_lowercase=True, help_text=_("Internal use tags sepcifically for maintaining parity with product. This field will be present as a subset in the tags field"))

    class Meta:
        ordering = ["-target_start"]
        indexes = [
            models.Index(fields=["product", "active"]),
        ]

    def __str__(self):
        return "Engagement {}: {} ({})".format(self.id if id else 0, self.name or "",
                                        self.target_start.strftime(
                                            "%b %d, %Y"))

    def get_absolute_url(self):
        return reverse("view_engagement", args=[str(self.id)])

    def copy(self):
        from dojo.models import Test, copy_model_util  # noqa: PLC0415 -- lazy import, avoids circular dependency
        copy = copy_model_util(self)
        # Save the necessary ManyToMany relationships
        old_notes = list(self.notes.all())
        old_files = list(self.files.all())
        old_tags = list(self.tags.all())
        old_risk_acceptances = list(self.risk_acceptance.all())
        old_tests = list(Test.objects.filter(engagement=self))
        # Save the object before setting any ManyToMany relationships
        copy.save()
        # Copy the notes
        for notes in old_notes:
            copy.notes.add(notes.copy())
        # Copy the files
        for files in old_files:
            copy.files.add(files.copy())
        # Copy the tests
        for test in old_tests:
            test.copy(engagement=copy)
        # Copy the risk_acceptances
        for risk_acceptance in old_risk_acceptances:
            copy.risk_acceptance.add(risk_acceptance.copy(engagement=copy))
        # Assign any tags
        copy.tags.set(old_tags)

        return copy

    def is_overdue(self):
        overdue_grace_days = 10 if self.engagement_type == "CI/CD" else 0

        max_end_date = timezone.now() - relativedelta(days=overdue_grace_days)

        return self.target_end < max_end_date.date()

    def get_breadcrumbs(self):
        bc = self.product.get_breadcrumbs()
        bc += [{"title": str(self),
                "url": reverse("view_engagement", args=(self.id,))}]
        return bc

    # only used by bulk risk acceptance api
    @property
    def unaccepted_open_findings(self):
        from dojo.models import Finding  # noqa: PLC0415 -- lazy import, avoids circular dependency
        from dojo.utils import get_system_setting  # noqa: PLC0415 circular import

        findings = Finding.objects.filter(risk_accepted=False, active=True, duplicate=False, test__engagement=self)
        if get_system_setting("enforce_verified_status", True) or get_system_setting("enforce_verified_status_metrics", True):
            findings = findings.filter(verified=True)

        return findings

    def accept_risks(self, accepted_risks):
        self.risk_acceptance.add(*accepted_risks)

    @property
    def has_jira_issue(self):
        from dojo.jira import services as jira_services  # noqa: PLC0415 circular import
        return jira_services.has_issue(self)

    @property
    def is_ci_cd(self):
        return self.engagement_type == "CI/CD"

    def delete(self, *args, **kwargs):
        logger.debug("%d engagement delete", self.id)
        from dojo.finding import helper as finding_helper  # noqa: PLC0415 circular import
        finding_helper.prepare_duplicates_for_delete(self)
        super().delete(*args, **kwargs)
        from dojo.models import Product  # noqa: PLC0415 -- lazy import, avoids circular dependency
        with suppress(Engagement.DoesNotExist, Product.DoesNotExist):
            # Suppressing a potential issue created from async delete removing
            # related objects in a separate task
            from dojo.utils import perform_product_grading  # noqa: PLC0415 circular import
            perform_product_grading(self.product)
