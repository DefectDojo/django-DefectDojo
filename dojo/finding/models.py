import base64
import hashlib
import logging
import re
from contextlib import suppress
from datetime import datetime
from typing import TYPE_CHECKING

import dateutil
from dateutil.parser import parse as datetutilsparse
from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.html import escape
from django.utils.translation import gettext as _
from django_extensions.db.models import TimeStampedModel
from tagulous.models import TagField
from titlecase import titlecase

from dojo.base_models.base import BaseModel

# get_current_date/tomorrow/copy_model_util are defined early in dojo.models, before the
# re-export that loads this module — so this resolves despite the partial circular load, and
# keeps their dojo.models.* path for Django migration serialization (used as field defaults).
from dojo.models import copy_model_util, get_current_date, tomorrow
from dojo.validators import cvss3_validator, cvss4_validator

if TYPE_CHECKING:
    from dojo.importers.location_manager import UnsavedLocation

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


class Finding(BaseModel):
    # Fields loaded when performing deduplication (used by get_finding_models_for_deduplication
    # and build_candidate_scope_queryset to restrict the SELECT to only what is needed).
    # Covers the union of all deduplication algorithms so that a single queryset works
    # regardless of which algorithm is in use.  Large text fields (description, mitigation,
    # impact, references, …) are intentionally excluded.
    DEDUPLICATION_FIELDS = [
        "id",
        # FK required for select_related("test") — must not be deferred
        "test",
        # Fields written by set_duplicate
        "duplicate",
        "active",
        "verified",
        "duplicate_finding",
        # Guard checks in set_duplicate
        "is_mitigated",
        "mitigated",
        "out_of_scope",
        "false_p",
        # Accessed by status() (debug logging only)
        "under_review",
        "risk_accepted",
        # Used by hash-code and legacy algorithms for endpoint/location matching
        "dynamic_finding",
        "static_finding",
        # Algorithm-specific matching fields
        "hash_code",            # hash_code, uid_or_hash, legacy
        "unique_id_from_tool",  # unique_id, uid_or_hash
        "title",                # legacy
        "cwe",                  # legacy
        "file_path",            # legacy
        "line",                 # legacy
    ]

    # Large text fields deferred in build_candidate_scope_queryset.  These are
    # never accessed during deduplication or reimport candidate matching, so
    # excluding them reduces the data loaded for every candidate finding.
    DEDUPLICATION_DEFERRED_FIELDS = [
        "description",
        "mitigation",
        "impact",
        "steps_to_reproduce",
        "severity_justification",
        "references",
        "url",
        "cvssv3",
        "cvssv4",
    ]

    title = models.CharField(max_length=511,
                             verbose_name=_("Title"),
                             help_text=_("A short description of the flaw."))
    date = models.DateField(default=get_current_date,
                            verbose_name=_("Date"),
                            help_text=_("The date the flaw was discovered."))
    sla_start_date = models.DateField(
                            blank=True,
                            null=True,
                            verbose_name=_("SLA Start Date"),
                            help_text=_("(readonly)The date used as start date for SLA calculation. Set by expiring risk acceptances. Empty by default, causing a fallback to 'date'."))
    sla_expiration_date = models.DateField(
                            blank=True,
                            null=True,
                            verbose_name=_("SLA Expiration Date"),
                            help_text=_("(readonly)The date SLA expires for this finding. Empty by default, causing a fallback to 'date'."))
    cwe = models.IntegerField(default=0, null=True, blank=True,
                              verbose_name=_("CWE"),
                              help_text=_("The CWE number associated with this flaw."))
    cve = models.CharField(max_length=50,
                           null=True,
                           blank=False,
                           verbose_name=_("Vulnerability Id"),
                           help_text=_("An id of a vulnerability in a security advisory associated with this finding. Can be a Common Vulnerabilities and Exposures (CVE) or from other sources."))
    epss_score = models.FloatField(default=None, null=True, blank=True,
                              verbose_name=_("EPSS Score"),
                              help_text=_("EPSS score for the CVE. Describes how likely it is the vulnerability will be exploited in the next 30 days."),
                              validators=[MinValueValidator(0.0), MaxValueValidator(1.0)])
    epss_percentile = models.FloatField(default=None, null=True, blank=True,
                              verbose_name=_("EPSS percentile"),
                              help_text=_("EPSS percentile for the CVE. Describes how many CVEs are scored at or below this one."),
                              validators=[MinValueValidator(0.0), MaxValueValidator(1.0)])
    known_exploited = models.BooleanField(default=False,
                                          verbose_name=_("Known Exploited"),
                                          help_text=_("Whether this vulnerability is known to have been exploited in the wild."))
    ransomware_used = models.BooleanField(default=False,
                                          verbose_name=_("Used in Ransomware"),
                                          help_text=_("Whether this vulnerability is known to have been leveraged as part of a ransomware campaign."))
    kev_date = models.DateField(null=True, blank=True,
                                verbose_name=_("KEV Date Added"),
                                help_text=_("The date the vulnerability was added to the KEV catalog."),
                                validators=[MaxValueValidator(tomorrow)])
    cvssv3 = models.TextField(validators=[cvss3_validator],
                              max_length=117,
                              null=True,
                              verbose_name=_("CVSS3 Vector"),
                              help_text=_("Common Vulnerability Scoring System version 3 (CVSS3) score associated with this finding."))
    cvssv3_score = models.FloatField(null=True,
                                        blank=True,
                                        verbose_name=_("CVSS3 Score"),
                                        help_text=_("Numerical CVSSv3 score for the vulnerability. If the vector is given, the score is updated while saving the finding. The value must be between 0-10."),
                                        validators=[MinValueValidator(0.0), MaxValueValidator(10.0)])

    cvssv4 = models.TextField(validators=[cvss4_validator],
                              max_length=255,
                              null=True,
                              verbose_name=_("CVSS4 vector"),
                              help_text=_("Common Vulnerability Scoring System version 4 (CVSS4) score associated with this finding."))
    cvssv4_score = models.FloatField(null=True,
                                        blank=True,
                                        verbose_name=_("CVSSv4 Score"),
                                        help_text=_("Numerical CVSSv4 score for the vulnerability. If the vector is given, the score is updated while saving the finding. The value must be between 0-10."),
                                        validators=[MinValueValidator(0.0), MaxValueValidator(10.0)])

    url = models.TextField(null=True,
                           blank=True,
                           editable=False,
                           verbose_name=_("URL"),
                           help_text=_("External reference that provides more information about this flaw."))  # not displayed and pretty much the same as references. To remove?
    severity = models.CharField(max_length=200,
                                verbose_name=_("Severity"),
                                help_text=_("The severity level of this flaw (Critical, High, Medium, Low, Info)."))
    description = models.TextField(verbose_name=_("Description"),
                                help_text=_("Longer more descriptive information about the flaw."))
    mitigation = models.TextField(verbose_name=_("Mitigation"),
                                null=True,
                                blank=True,
                                help_text=_("Text describing how to best fix the flaw."))
    fix_available = models.BooleanField(null=True,
                                        default=None,
                                        verbose_name=_("Fix Available"),
                                        help_text=_("Denotes if there is a fix available for this flaw."))
    fix_version = models.CharField(null=True,
                                         blank=True,
                                         max_length=100,
                                         verbose_name=_("Fix version"),
                                         help_text=_("Version of the affected component in which the flaw is fixed."))
    impact = models.TextField(verbose_name=_("Impact"),
                                null=True,
                                blank=True,
                                help_text=_("Text describing the impact this flaw has on systems, products, enterprise, etc."))
    steps_to_reproduce = models.TextField(null=True,
                                          blank=True,
                                          verbose_name=_("Steps to Reproduce"),
                                          help_text=_("Text describing the steps that must be followed in order to reproduce the flaw / bug."))
    severity_justification = models.TextField(null=True,
                                              blank=True,
                                              verbose_name=_("Severity Justification"),
                                              help_text=_("Text describing why a certain severity was associated with this flaw."))
    # TODO: Delete this after the move to Locations
    endpoints = models.ManyToManyField("dojo.Endpoint",
                                       blank=True,
                                       verbose_name=_("Endpoints"),
                                       help_text=_("The hosts within the product that are susceptible to this flaw. + The status of the endpoint associated with this flaw (Vulnerable, Mitigated, ...)."),
                                       through="dojo.Endpoint_Status")
    references = models.TextField(null=True,
                                  blank=True,
                                  db_column="refs",
                                  verbose_name=_("References"),
                                  help_text=_("The external documentation available for this flaw."))
    test = models.ForeignKey("dojo.Test",
                             editable=False,
                             on_delete=models.CASCADE,
                             verbose_name=_("Test"),
                             help_text=_("The test that is associated with this flaw."))
    active = models.BooleanField(default=True,
                                 verbose_name=_("Active"),
                                 help_text=_("Denotes if this flaw is active or not."))
    # note that false positive findings cannot be verified
    # in defectdojo verified means: "we have verified the finding and it turns out that it's not a false positive"
    verified = models.BooleanField(default=False,
                                   verbose_name=_("Verified"),
                                   help_text=_("Denotes if this flaw has been manually verified by the tester."))
    false_p = models.BooleanField(default=False,
                                  verbose_name=_("False Positive"),
                                  help_text=_("Denotes if this flaw has been deemed a false positive by the tester."))
    duplicate = models.BooleanField(default=False,
                                    verbose_name=_("Duplicate"),
                                    help_text=_("Denotes if this flaw is a duplicate of other flaws reported."))
    duplicate_finding = models.ForeignKey("self",
                                          editable=False,
                                          null=True,
                                          related_name="original_finding",
                                          blank=True, on_delete=models.DO_NOTHING,
                                          verbose_name=_("Duplicate Finding"),
                                          help_text=_("Link to the original finding if this finding is a duplicate."))
    out_of_scope = models.BooleanField(default=False,
                                       verbose_name=_("Out Of Scope"),
                                       help_text=_("Denotes if this flaw falls outside the scope of the test and/or engagement."))
    risk_accepted = models.BooleanField(default=False,
                                       verbose_name=_("Risk Accepted"),
                                       help_text=_("Denotes if this finding has been marked as an accepted risk."))
    under_review = models.BooleanField(default=False,
                                       verbose_name=_("Under Review"),
                                       help_text=_("Denotes is this flaw is currently being reviewed."))

    last_status_update = models.DateTimeField(editable=False,
                                            null=True,
                                            blank=True,
                                            auto_now_add=True,
                                            verbose_name=_("Last Status Update"),
                                            help_text=_("Timestamp of latest status update (change in status related fields)."))

    review_requested_by = models.ForeignKey("dojo.Dojo_User",
                                            null=True,
                                            blank=True,
                                            related_name="review_requested_by",
                                            on_delete=models.RESTRICT,
                                            verbose_name=_("Review Requested By"),
                                            help_text=_("Documents who requested a review for this finding."))
    reviewers = models.ManyToManyField("dojo.Dojo_User",
                                       blank=True,
                                       verbose_name=_("Reviewers"),
                                       help_text=_("Documents who reviewed the flaw."))

    # Defect Tracking Review
    under_defect_review = models.BooleanField(default=False,
                                              verbose_name=_("Under Defect Review"),
                                              help_text=_("Denotes if this finding is under defect review."))
    defect_review_requested_by = models.ForeignKey("dojo.Dojo_User",
                                                   null=True,
                                                   blank=True,
                                                   related_name="defect_review_requested_by",
                                                   on_delete=models.RESTRICT,
                                                   verbose_name=_("Defect Review Requested By"),
                                                   help_text=_("Documents who requested a defect review for this flaw."))
    is_mitigated = models.BooleanField(default=False,
                                       verbose_name=_("Is Mitigated"),
                                       help_text=_("Denotes if this flaw has been fixed."))
    thread_id = models.IntegerField(default=0,
                                    editable=False,
                                    verbose_name=_("Thread ID"))
    mitigated = models.DateTimeField(editable=False,
                                     null=True,
                                     blank=True,
                                     verbose_name=_("Mitigated"),
                                     help_text=_("Denotes if this flaw has been fixed by storing the date it was fixed."))
    mitigated_by = models.ForeignKey("dojo.Dojo_User",
                                     null=True,
                                     editable=False,
                                     related_name="mitigated_by",
                                     on_delete=models.RESTRICT,
                                     verbose_name=_("Mitigated By"),
                                     help_text=_("Documents who has marked this flaw as fixed."))

    class ProcessingStatus(models.TextChoices):
        PENDING = "pending", _("Pending")
        PROCESSED = "processed", _("Processed")
        FAILED = "failed", _("Failed")

    # Post-import processing lifecycle (deduplication, rules, integrations).
    # Importers create findings as PENDING; the post-processing batch task stamps
    # PROCESSED on completion or FAILED on error. Findings created outside the
    # import pipeline (manual entry, API) default to PROCESSED.
    processing_status = models.CharField(max_length=10,
                                         choices=ProcessingStatus.choices,
                                         default=ProcessingStatus.PROCESSED,
                                         editable=False,
                                         verbose_name=_("Processing Status"),
                                         help_text=_("State of post-import processing (deduplication, rules, integrations) for this finding."))
    processed_at = models.DateTimeField(null=True,
                                        blank=True,
                                        editable=False,
                                        verbose_name=_("Processed At"),
                                        help_text=_("When post-import processing last completed for this finding."))
    processing_error = models.TextField(blank=True,
                                        default="",
                                        editable=False,
                                        verbose_name=_("Processing Error"),
                                        help_text=_("Why post-import processing failed for this finding (e.g. the JIRA push error). Empty unless processing_status is failed."))
    reporter = models.ForeignKey("dojo.Dojo_User",
                                 editable=False,
                                 default=1,
                                 related_name="reporter",
                                 on_delete=models.RESTRICT,
                                 verbose_name=_("Reporter"),
                                 help_text=_("Documents who reported the flaw."))
    notes = models.ManyToManyField("dojo.Notes",
                                   blank=True,
                                   editable=False,
                                   verbose_name=_("Notes"),
                                   help_text=_("Stores information pertinent to the flaw or the mitigation."))
    numerical_severity = models.CharField(max_length=4,
                                          verbose_name=_("Numerical Severity"),
                                          help_text=_("The numerical representation of the severity (S0, S1, S2, S3, S4)."))
    last_reviewed = models.DateTimeField(null=True,
                                         editable=False,
                                         verbose_name=_("Last Reviewed"),
                                         help_text=_("Provides the date the flaw was last 'touched' by a tester."))
    last_reviewed_by = models.ForeignKey("dojo.Dojo_User",
                                         null=True,
                                         editable=False,
                                         related_name="last_reviewed_by",
                                         on_delete=models.RESTRICT,
                                         verbose_name=_("Last Reviewed By"),
                                         help_text=_("Provides the person who last reviewed the flaw."))
    files = models.ManyToManyField("dojo.FileUpload",
                                   blank=True,
                                   editable=False,
                                   verbose_name=_("Files"),
                                   help_text=_("Files(s) related to the flaw."))
    param = models.TextField(null=True,
                             blank=True,
                             editable=False,
                             verbose_name=_("Parameter"),
                             help_text=_("Parameter used to trigger the issue (DAST)."))
    payload = models.TextField(null=True,
                               blank=True,
                               editable=False,
                               verbose_name=_("Payload"),
                               help_text=_("Payload used to attack the service / application and trigger the bug / problem."))
    hash_code = models.CharField(null=True,
                                 blank=True,
                                 editable=False,
                                 max_length=64,
                                 verbose_name=_("Hash Code"),
                                 help_text=_("A hash over a configurable set of fields that is used for findings deduplication."))
    line = models.IntegerField(null=True,
                               blank=True,
                               verbose_name=_("Line number"),
                               help_text=_("Source line number of the attack vector."))
    file_path = models.CharField(null=True,
                                 blank=True,
                                 max_length=4000,
                                 verbose_name=_("File path"),
                                 help_text=_("Identified file(s) containing the flaw."))
    component_name = models.CharField(null=True,
                                      blank=True,
                                      max_length=500,
                                      verbose_name=_("Component name"),
                                      help_text=_("Name of the affected component (library name, part of a system, ...)."))
    component_version = models.CharField(null=True,
                                         blank=True,
                                         max_length=100,
                                         verbose_name=_("Component version"),
                                         help_text=_("Version of the affected component."))
    found_by = models.ManyToManyField("dojo.Test_Type",
                                      editable=False,
                                      verbose_name=_("Found by"),
                                      help_text=_("The name of the scanner that identified the flaw."))
    static_finding = models.BooleanField(default=False,
                                         verbose_name=_("Static finding (SAST)"),
                                         help_text=_("Flaw has been detected from a Static Application Security Testing tool (SAST)."))
    dynamic_finding = models.BooleanField(default=True,
                                          verbose_name=_("Dynamic finding (DAST)"),
                                          help_text=_("Flaw has been detected from a Dynamic Application Security Testing tool (DAST)."))
    scanner_confidence = models.IntegerField(null=True,
                                             blank=True,
                                             default=None,
                                             editable=False,
                                             verbose_name=_("Scanner confidence"),
                                             help_text=_("Confidence level of vulnerability which is supplied by the scanner."))
    sonarqube_issue = models.ForeignKey("dojo.Sonarqube_Issue",
                                        null=True,
                                        blank=True,
                                        help_text=_("The SonarQube issue associated with this finding."),
                                        verbose_name=_("SonarQube issue"),
                                        on_delete=models.CASCADE)
    unique_id_from_tool = models.CharField(null=True,
                                           blank=True,
                                           max_length=500,
                                           verbose_name=_("Unique ID from tool"),
                                           help_text=_("Vulnerability technical id from the source tool. Allows to track unique vulnerabilities over time across subsequent scans."))
    vuln_id_from_tool = models.CharField(null=True,
                                         blank=True,
                                         max_length=500,
                                         verbose_name=_("Vulnerability ID from tool"),
                                         help_text=_("Non-unique technical id from the source tool associated with the vulnerability type."))
    sast_source_object = models.CharField(null=True,
                                          blank=True,
                                          max_length=500,
                                          verbose_name=_("SAST Source Object"),
                                          help_text=_("Source object (variable, function...) of the attack vector."))
    sast_sink_object = models.CharField(null=True,
                                        blank=True,
                                        max_length=500,
                                        verbose_name=_("SAST Sink Object"),
                                        help_text=_("Sink object (variable, function...) of the attack vector."))
    sast_source_line = models.IntegerField(null=True,
                                           blank=True,
                                           verbose_name=_("SAST Source Line number"),
                                           help_text=_("Source line number of the attack vector."))
    sast_source_file_path = models.CharField(null=True,
                                             blank=True,
                                             max_length=4000,
                                             verbose_name=_("SAST Source File Path"),
                                             help_text=_("Source file path of the attack vector."))
    nb_occurences = models.IntegerField(null=True,
                                        blank=True,
                                        verbose_name=_("Number of occurences"),
                                        help_text=_("Number of occurences in the source tool when several vulnerabilites were found and aggregated by the scanner."))

    # this is useful for vulnerabilities on dependencies : helps answer the question "Did I add this vulnerability or was it discovered recently?"
    publish_date = models.DateField(null=True,
                                         blank=True,
                                         verbose_name=_("Publish date"),
                                         help_text=_("Date when this vulnerability was made publicly available."))

    # The service is used to generate the hash_code, so that it gets part of the deduplication of findings.
    service = models.CharField(null=True,
                               blank=True,
                               max_length=200,
                               verbose_name=_("Service"),
                               help_text=_("A service is a self-contained piece of functionality within a Product. This is an optional field which is used in deduplication of findings when set."))

    planned_remediation_date = models.DateField(null=True,
                                                editable=True,
                                                verbose_name=_("Planned Remediation Date"),
                                                help_text=_("The date the flaw is expected to be remediated."))

    planned_remediation_version = models.CharField(null=True,
                                        blank=True,
                                        max_length=99,
                                        verbose_name=_("Planned remediation version"),
                                        help_text=_("The target version when the vulnerability should be fixed / remediated"))

    effort_for_fixing = models.CharField(null=True,
                                blank=True,
                                max_length=99,
                                verbose_name=_("Effort for fixing"),
                                help_text=_("Effort for fixing / remediating the vulnerability (Low, Medium, High)"))

    tags = TagField(blank=True, force_lowercase=True, help_text=_("Add tags that help describe this finding. Choose from the list or add new tags. Press Enter key to add."))
    inherited_tags = TagField(blank=True, force_lowercase=True, help_text=_("Internal use tags sepcifically for maintaining parity with product. This field will be present as a subset in the tags field"))

    SEVERITIES = {"Info": 4, "Low": 3, "Medium": 2,
                  "High": 1, "Critical": 0}

    class Meta:
        ordering = ("numerical_severity", "-date", "title", "epss_score", "epss_percentile")
        indexes = [
            models.Index(fields=["test", "active", "verified"]),

            models.Index(fields=["test", "is_mitigated"]),
            models.Index(fields=["test", "duplicate"]),
            models.Index(fields=["test", "out_of_scope"]),
            models.Index(fields=["test", "false_p"]),

            models.Index(fields=["test", "unique_id_from_tool", "duplicate"]),
            models.Index(fields=["test", "hash_code", "duplicate"]),

            models.Index(fields=["test", "component_name"]),

            models.Index(fields=["cve"]),
            models.Index(fields=["epss_score"]),
            models.Index(fields=["epss_percentile"]),
            models.Index(fields=["cwe"]),
            models.Index(fields=["out_of_scope"]),
            models.Index(fields=["false_p"]),
            models.Index(fields=["verified"]),
            models.Index(fields=["mitigated"]),
            models.Index(fields=["active"]),
            models.Index(fields=["numerical_severity"]),
            models.Index(fields=["date"]),
            models.Index(fields=["title"]),
            models.Index(fields=["hash_code"]),
            models.Index(fields=["unique_id_from_tool"]),
            # Partial index: the PENDING working set is small and hot; PROCESSED
            # rows (the vast majority) never enter the index.
            models.Index(fields=["processing_status"],
                         name="finding_procstatus_pending",
                         condition=models.Q(processing_status="pending")),
            # models.Index(fields=['file_path']), # can't add index because the field has max length 4000.
            models.Index(fields=["line"]),
            models.Index(fields=["component_name"]),
            models.Index(fields=["duplicate"]),
            models.Index(fields=["is_mitigated"]),
            models.Index(fields=["duplicate_finding", "id"]),
            models.Index(fields=["known_exploited"]),
            models.Index(fields=["ransomware_used"]),
            models.Index(fields=["kev_date"]),
            models.Index(
                fields=["severity", "-numerical_severity"],
                name="idx_finding_sev_active",
                condition=models.Q(active=True),
            ),
            models.Index(
                fields=["-date"],
                name="idx_finding_riskaccepted_date",
                condition=models.Q(risk_accepted=True),
            ),
            models.Index(
                fields=["test", "date"],
                name="idx_finding_testid_date",
            ),
            models.Index(
                fields=["sla_expiration_date", "test"],
                name="idx_finding_sla_open_cov",
                condition=models.Q(is_mitigated=False),
            ),
            models.Index(
                fields=["severity"],
                name="idx_finding_open_active_sev",
                condition=models.Q(active=True, is_mitigated=False),
            ),
            models.Index(
                fields=["severity", "-numerical_severity"],
                name="idx_finding_sev_open_unver",
                condition=models.Q(active=True, verified=False),
            ),
            models.Index(
                fields=["test", "sla_expiration_date", "date"],
                name="idx_finding_sla_breach_cov",
                include=["id"],
                condition=models.Q(is_mitigated=False),
            ),
            # Full (non-partial) index so the global finding list ordered by
            # sla_expiration_date can be served by an index walk + LIMIT instead
            # of sorting the entire authorized finding set. The partial
            # idx_finding_sla_open_cov can't serve it (query has no is_mitigated
            # filter).
            models.Index(
                fields=["sla_expiration_date"],
                name="idx_finding_sla_exp",
            ),
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if settings.V3_FEATURE_LOCATIONS:
            self.unsaved_locations: list[UnsavedLocation] = []
        else:
            # TODO: Delete this after the move to Locations
            self.unsaved_endpoints = []
        self.unsaved_request = None
        self.unsaved_response = None
        self.unsaved_tags = None
        self.unsaved_files = None
        self.unsaved_vulnerability_ids = None

    def __str__(self):
        return self.title

    def save(self, dedupe_option=True, rules_option=True, product_grading_option=True,  # noqa: FBT002
             issue_updater_option=True, push_to_jira=False, user=None, *args, **kwargs):  # noqa: FBT002 - this is bit hard to fix nice have this universally fixed
        logger.debug("Start saving finding of id " + str(self.id) + " dedupe_option:" + str(dedupe_option) + " (self.pk is %s)", "None" if self.pk is None else "not None")
        from dojo.finding import helper as finding_helper  # noqa: PLC0415 -- lazy import, avoids circular dependency

        is_new_finding = self.pk is None

        # if not isinstance(self.date, (datetime, date)):
        #     raise ValidationError(_("The 'date' field must be a valid date or datetime object."))

        if not user:
            from dojo.utils import get_current_user  # noqa: PLC0415 -- lazy import, avoids circular dependency
            user = get_current_user()
        # Title Casing
        self.title = titlecase(self.title[:511])
        # Normalize blank component fields to NULL so that findings without a component
        # group together. An empty string is treated as a distinct value from NULL by the
        # database, which would otherwise produce a separate "None" component group (SC-13073).
        if self.component_name is not None and not self.component_name.strip():
            self.component_name = None
        if self.component_version is not None and not self.component_version.strip():
            self.component_version = None
        # Set the date of the finding if nothing is supplied
        if self.date is None:
            self.date = timezone.now()
        # Assign the numerical severity for correct sorting order
        self.numerical_severity = Finding.get_numerical_severity(self.severity)

        # Synchronize cvssv3 score using cvssv3 vector

        if self.cvssv3:
            try:
                from dojo.utils import parse_cvss_data  # noqa: PLC0415 -- lazy import, avoids circular dependency
                cvss_data = parse_cvss_data(self.cvssv3)
                if cvss_data:
                    self.cvssv3 = cvss_data.get("cvssv3")
                    self.cvssv3_score = cvss_data.get("cvssv3_score")

            except Exception as ex:
                logger.warning("Can't compute cvssv3 score for finding id %i. Invalid cvssv3 vector found: '%s'. Exception: %s.", self.id, self.cvssv3, ex)
                # remove invalid cvssv3 vector for new findings, or should we just throw a ValidationError?
                if self.pk is None:
                    self.cvssv3 = None

        # behaviour for CVVS4 is slightly different. Extracting this into a method would lead to probably hard to read code
        if self.cvssv4:
            try:
                from dojo.utils import parse_cvss_data  # noqa: PLC0415 -- lazy import, avoids circular dependency
                cvss_data = parse_cvss_data(self.cvssv4)
                if cvss_data:
                    self.cvssv4 = cvss_data.get("cvssv4")
                    self.cvssv4_score = cvss_data.get("cvssv4_score")

            except Exception as ex:
                logger.warning("Can't compute cvssv4 score for finding id %i. Invalid cvssv4 vector found: '%s'. Exception: %s.", self.id, self.cvssv4, ex)
                self.cvssv4 = None

        self.set_hash_code(dedupe_option)

        if is_new_finding:
            if settings.V3_FEATURE_LOCATIONS:
                if (self.file_path is not None) and (len(self.unsaved_locations) == 0):
                    self.static_finding = True
                    self.dynamic_finding = False
                elif (self.file_path is not None):
                    self.static_finding = True
            # TODO: Delete this after the move to Locations
            elif (self.file_path is not None) and (len(self.unsaved_endpoints) == 0):
                self.static_finding = True
                self.dynamic_finding = False
            elif (self.file_path is not None):
                self.static_finding = True

            # because we have reduced the number of (super()).save() calls, the helper is no longer called for new findings
            # so we call it manually
            finding_helper.update_finding_status(self, user, changed_fields={"id": (None, None)})

        # logger.debug('setting static / dynamic in save')
        # need to have an id/pk before we can access locations/endpoints
        elif self.file_path is not None:
            if settings.V3_FEATURE_LOCATIONS:
                if not self.locations.exists():
                    self.static_finding = True
                    self.dynamic_finding = False
                else:
                    self.static_finding = True
            # TODO: Delete this after the move to Locations
            elif not self.endpoints.exists():
                self.static_finding = True
                self.dynamic_finding = False
            else:
                self.static_finding = True

        # update the SLA expiration date last, after all other finding fields have been updated
        self.set_sla_expiration_date()

        logger.debug("Saving finding of id " + str(self.id) + " dedupe_option:" + str(dedupe_option) + " (self.pk is %s)", "None" if self.pk is None else "not None")
        # We cannot run the full_clean method here without issue, so we specify skip_validation
        super().save(*args, **kwargs, skip_validation=True)

        # Only add to found_by for newly-created findings (avoid doing this on every update)
        if is_new_finding:
            self.found_by.add(self.test.test_type)

        # only perform post processing (in celery task) if needed. this check avoids submitting 1000s of tasks to celery that will do nothing
        from dojo.models import System_Settings  # noqa: PLC0415 -- lazy import, avoids circular dependency
        system_settings = System_Settings.objects.get()
        if dedupe_option or issue_updater_option or (product_grading_option and system_settings.enable_product_grade) or push_to_jira:
            finding_helper.post_process_finding_save(self.id, dedupe_option=dedupe_option, rules_option=rules_option, product_grading_option=product_grading_option,
                issue_updater_option=issue_updater_option, push_to_jira=push_to_jira, user=user, *args, **kwargs)
        else:
            logger.debug("no options selected that require finding post processing")

    def get_absolute_url(self):
        return reverse("view_finding", args=[str(self.id)])

    def copy(self, test=None):
        copy = copy_model_util(self)
        # Save the necessary ManyToMany relationships
        old_notes = list(self.notes.all())
        old_files = list(self.files.all())
        old_reviewers = list(self.reviewers.all())
        old_found_by = list(self.found_by.all())
        old_tags = list(self.tags.all())
        # Wipe the IDs of the new object
        if test:
            copy.test = test
        # Save the object before setting any ManyToMany relationships
        copy.save()
        # Copy the notes
        for notes in old_notes:
            copy.notes.add(notes.copy())
        # Copy the files
        for files in old_files:
            copy.files.add(files.copy())
        if settings.V3_FEATURE_LOCATIONS:
            old_location_refs = self.locations.all()
            for location_ref in old_location_refs:
                location_ref.copy(copy)
        else:
            # TODO: Delete this after the move to Locations
            # Copy the endpoint_status
            old_status_findings = list(self.status_finding.all())
            for endpoint_status in old_status_findings:
                endpoint_status.copy(finding=copy)  # adding or setting is not necessary, link is created by Endpoint_Status.copy()
        # Assign any reviewers
        copy.reviewers.set(old_reviewers)
        # Assign any found_by
        copy.found_by.set(old_found_by)
        # Assign any tags
        copy.tags.set(old_tags)

        return copy

    def delete(self, *args, product_grading_option=True, **kwargs):
        logger.debug("%d finding delete", self.id)
        from dojo.finding import helper as finding_helper  # noqa: PLC0415 -- lazy import, avoids circular dependency
        finding_helper.finding_delete(self)
        super().delete(*args, **kwargs)
        if product_grading_option:
            from dojo.models import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
                Engagement,
                Product,
                Test,
            )
            with suppress(Finding.DoesNotExist, Test.DoesNotExist, Engagement.DoesNotExist, Product.DoesNotExist):
                # Suppressing a potential issue created from async delete removing
                # related objects in a separate task
                from dojo.utils import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
                    perform_product_grading,
                )
                perform_product_grading(self.test.engagement.product)

    # only used by bulk risk acceptance api
    @classmethod
    def unaccepted_open_findings(cls):
        from dojo.utils import get_system_setting  # noqa: PLC0415 -- lazy import, avoids circular dependency
        results = cls.objects.filter(active=True, duplicate=False, risk_accepted=False)
        if get_system_setting("enforce_verified_status", True) or get_system_setting("enforce_verified_status_metrics", True):
            results = results.filter(verified=True)

        return results

    @property
    def risk_acceptance(self):
        ras = self.risk_acceptance_set.all()
        if ras:
            return ras[0]

        return None

    def compute_hash_code(self):
        # Allow Pro to overwrite compute hash_code which gets dedupe settings from a database instead of django.settings
        from dojo.utils import get_custom_method  # noqa: PLC0415 -- lazy import, avoids circular dependency
        if compute_hash_code_method := get_custom_method("FINDING_COMPUTE_HASH_METHOD"):
            deduplicationLogger.debug("using custom FINDING_COMPUTE_HASH_METHOD method")
            return compute_hash_code_method(self)

        # Check if all needed settings are defined
        if not hasattr(settings, "HASHCODE_FIELDS_PER_SCANNER") or not hasattr(settings, "HASHCODE_ALLOWS_NULL_CWE") or not hasattr(settings, "HASHCODE_ALLOWED_FIELDS"):
            deduplicationLogger.debug("no or incomplete configuration per hash_code found; using legacy algorithm")
            return self.compute_hash_code_legacy()

        hash_code_fields = self.test.hash_code_fields

        # Check if hash_code fields are found in the settings
        if not hash_code_fields:
            deduplicationLogger.debug(
                "No configuration for hash_code computation found; using default fields for " + ("dynamic" if self.dynamic_finding else "static") + " scanners")
            return self.compute_hash_code_legacy()

        # Check if all elements of HASHCODE_FIELDS_PER_SCANNER are in HASHCODE_ALLOWED_FIELDS
        if not (all(elem in settings.HASHCODE_ALLOWED_FIELDS for elem in hash_code_fields)):
            deduplicationLogger.debug(
                "compute_hash_code - configuration error: some elements of HASHCODE_FIELDS_PER_SCANNER are not in the allowed list HASHCODE_ALLOWED_FIELDS. "
                "Using default fields")
            return self.compute_hash_code_legacy()

        # Make sure that we have a cwe if we need one
        if self.cwe == 0 and not self.test.hash_code_allows_null_cwe:
            deduplicationLogger.debug(
                "Cannot compute hash_code based on configured fields because cwe is 0 for finding of title '" + self.title + "' found in file '" + str(self.file_path)
                + "'. Fallback to legacy mode for this finding.")
            return self.compute_hash_code_legacy()

        deduplicationLogger.debug("computing hash_code for finding id " + str(self.id) + " based on: " + ", ".join(hash_code_fields))

        fields_to_hash = ""
        for hashcodeField in hash_code_fields:
            # Note: preserve this field label ("endpoints") for settings purposes through the Locations migration
            if hashcodeField == "endpoints":
                # For locations/endpoints, need to compute the field
                locations = self.get_locations()
                fields_to_hash += locations
                deduplicationLogger.debug(hashcodeField + " : " + locations)
            elif hashcodeField == "vulnerability_ids":
                # For vulnerability_ids, need to compute the field
                my_vulnerability_ids = self.get_vulnerability_ids()
                fields_to_hash += my_vulnerability_ids
                deduplicationLogger.debug(hashcodeField + " : " + my_vulnerability_ids)
            else:
                # Generically use the finding attribute having the same name, converts to str in case it's integer
                fields_to_hash += str(getattr(self, hashcodeField))
                deduplicationLogger.debug(hashcodeField + " : " + str(getattr(self, hashcodeField)))

        # Log the hash_code fields that are always included (but are not part of the hash_code_fields list as they are inserted downtstream in self.hash_fields)
        hash_code_fields_always = getattr(settings, "HASH_CODE_FIELDS_ALWAYS", [])
        for hashcodeField in hash_code_fields_always:
            if getattr(self, hashcodeField):
                deduplicationLogger.debug(hashcodeField + " : " + str(getattr(self, hashcodeField)))

        deduplicationLogger.debug("compute_hash_code - fields_to_hash = " + fields_to_hash)
        return self.hash_fields(fields_to_hash)

    def compute_hash_code_legacy(self):
        fields_to_hash = self.title + str(self.cwe) + str(self.line) + str(self.file_path) + self.description
        deduplicationLogger.debug("compute_hash_code_legacy - fields_to_hash = " + fields_to_hash)
        return self.hash_fields(fields_to_hash)

    # Get vulnerability_ids to use for hash_code computation
    def get_vulnerability_ids(self):

        def _get_unsaved_vulnerability_ids(finding) -> str:
            if finding.unsaved_vulnerability_ids:
                deduplicationLogger.debug("get_vulnerability_ids before the finding was saved")
                # convert list of unsaved vulnerability_ids to the list of their canonical representation
                vulnerability_id_str_list = [str(vulnerability_id) for vulnerability_id in finding.unsaved_vulnerability_ids]
                # deduplicate (usually done upon saving finding) and sort endpoints
                return "".join(sorted(dict.fromkeys(vulnerability_id_str_list)))
            deduplicationLogger.debug("finding has no unsaved vulnerability references")
            return ""

        def _get_saved_vulnerability_ids(finding) -> str:
            if finding.id is not None:
                # Use the reverse relation (vulnerability_id_set) rather than a fresh
                # Vulnerability_Id.objects.filter(...) so prefetch_related("vulnerability_id_set")
                # is honored — avoids an N+1 (COUNT + SELECT per finding) during dedupe/hashcode.
                vulnerability_id_str_list = [str(vulnerability_id) for vulnerability_id in finding.vulnerability_id_set.all()]
                deduplicationLogger.debug("get_vulnerability_ids after the finding was saved. Vulnerability references count: " + str(len(vulnerability_id_str_list)))
                # sort vulnerability_ids strings
                return "".join(sorted(vulnerability_id_str_list))
            return ""

        return _get_saved_vulnerability_ids(self) or _get_unsaved_vulnerability_ids(self)

    # Get locations/endpoints to use for hash_code computation
    def get_locations(self):
        # TODO: Delete this after the move to Locations
        if not settings.V3_FEATURE_LOCATIONS:
            # Get endpoints to use for hash_code computation
            # (This sometimes reports "None")
            def _get_unsaved_endpoints(finding) -> str:
                if len(finding.unsaved_endpoints) > 0:
                    deduplicationLogger.debug("get_endpoints before the finding was saved")
                    # convert list of unsaved endpoints to the list of their canonical representation
                    endpoint_str_list = [str(endpoint) for endpoint in finding.unsaved_endpoints]
                    # deduplicate (usually done upon saving finding) and sort endpoints
                    return "".join(dict.fromkeys(endpoint_str_list))
                # we can get here when the parser defines static_finding=True but leaves dynamic_finding defaulted
                # In this case, before saving the finding, both static_finding and dynamic_finding are True
                # After saving dynamic_finding may be set to False probably during the saving process (observed on Bandit scan before forcing dynamic_finding=False at parser level)
                deduplicationLogger.debug("trying to get endpoints on a finding before it was saved but no endpoints found (static parser wrongly identified as dynamic?")
                return ""

            def _get_saved_endpoints(finding) -> str:
                if finding.id is not None:
                    deduplicationLogger.debug("get_endpoints: after the finding was saved. Endpoints count: " + str(finding.endpoints.count()))
                    # convert list of endpoints to the list of their canonical representation
                    endpoint_str_list = [str(endpoint) for endpoint in finding.endpoints.all()]
                    # sort endpoints strings
                    return "".join(sorted(endpoint_str_list))
                return ""

            return _get_saved_endpoints(self) or _get_unsaved_endpoints(self)

        def _get_unsaved_locations(finding) -> str:
            if len(finding.unsaved_locations) > 0:
                deduplicationLogger.debug("get_locations before the finding was saved")
                # convert list of unsaved locations to the list of their canonical representation
                from dojo.importers.location_manager import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
                    LocationManager,
                )
                unsaved_locations = LocationManager.clean_unsaved_locations(finding.unsaved_locations)
                # deduplicate (usually done upon saving finding) and sort locations
                locations = sorted({location.get_location_value() for location in unsaved_locations})
                return "".join(locations)
            # we can get here when the parser defines static_finding=True but leaves dynamic_finding defaulted
            # In this case, before saving the finding, both static_finding and dynamic_finding are True
            # After saving dynamic_finding may be set to False probably during the saving process (observed on Bandit scan before forcing dynamic_finding=False at parser level)
            deduplicationLogger.debug("trying to get locations on a finding before it was saved but no locations found (static parser wrongly identified as dynamic?")
            return ""

        def _get_saved_locations(finding) -> str:
            if finding.id is not None:
                from dojo.url.models import URL  # noqa: PLC0415 -- lazy import, avoids circular dependency
                url_locations = finding.locations.filter(location__location_type=URL.get_location_type())
                deduplicationLogger.debug("get_locations: after the finding was saved. Locations count: " + str(url_locations.count()))
                # convert list of locations to the list of their canonical representation
                locations = sorted({location_ref.location.get_location_value() for location_ref in url_locations.all()})
                # sort locations strings
                return "".join(sorted(locations))
            return ""

        return _get_saved_locations(self) or _get_unsaved_locations(self)

    # Compute the hash_code from the fields to hash
    def hash_fields(self, fields_to_hash):
        if hasattr(settings, "HASH_CODE_FIELDS_ALWAYS"):
            for field in settings.HASH_CODE_FIELDS_ALWAYS:
                if getattr(self, field):
                    deduplicationLogger.debug("adding HASH_CODE_FIELDS_ALWAYSfield %s to hash_fields: %s", field, getattr(self, field))
                    fields_to_hash += str(getattr(self, field))

        logger.debug("fields_to_hash      : %s", fields_to_hash)
        logger.debug("fields_to_hash lower: %s", fields_to_hash.lower())
        return hashlib.sha256(fields_to_hash.casefold().encode("utf-8").strip()).hexdigest()

    def duplicate_finding_set(self):
        if self.duplicate:
            if self.duplicate_finding is not None:
                return Finding.objects.get(
                    id=self.duplicate_finding.id).original_finding.all().order_by("title")
            return []
        return self.original_finding.all().order_by("title")

    def get_scanner_confidence_text(self):
        if self.scanner_confidence and isinstance(self.scanner_confidence, int):
            if self.scanner_confidence <= 2:
                return "Certain"
            if self.scanner_confidence >= 3 and self.scanner_confidence <= 5:
                return "Firm"
            return "Tentative"
        return ""

    @staticmethod
    def get_numerical_severity(severity):
        if severity == "Critical":
            return "S0"
        if severity == "High":
            return "S1"
        if severity == "Medium":
            return "S2"
        if severity == "Low":
            return "S3"
        if severity == "Info":
            return "S4"
        return "S5"

    @staticmethod
    def get_number_severity(severity):
        if severity == "Critical":
            return 4
        if severity == "High":
            return 3
        if severity == "Medium":
            return 2
        if severity == "Low":
            return 1
        if severity == "Info":
            return 0
        return 5

    @staticmethod
    def get_severity(num_severity):
        severities = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
        if num_severity in severities:
            return severities[num_severity]

        return None

    def status(self):
        status = []
        if self.under_review:
            status += ["Under Review"]
        if self.active:
            status += ["Active"]
        else:
            status += ["Inactive"]
        if self.verified:
            status += ["Verified"]
        if self.mitigated or self.is_mitigated:
            status += ["Mitigated"]
        if self.false_p:
            status += ["False Positive"]
        if self.out_of_scope:
            status += ["Out Of Scope"]
        if self.duplicate:
            status += ["Duplicate"]
        if self.risk_accepted:
            status += ["Risk Accepted"]
        if not len(status):
            status += ["Initial"]

        return ", ".join([str(s) for s in status])

    def _age(self, start_date):
        if start_date and isinstance(start_date, str):
            start_date = datetutilsparse(start_date).date()

        if isinstance(start_date, datetime):
            start_date = start_date.date()

        if self.mitigated:
            mitigated_date = self.mitigated
            if isinstance(mitigated_date, datetime):
                mitigated_date = self.mitigated.date()
            diff = mitigated_date - start_date
        else:
            diff = get_current_date() - start_date
        days = diff.days
        return max(0, days)

    @property
    def age(self):
        return self._age(self.date)

    @property
    def sla_age(self):
        return self._age(self.get_sla_start_date())

    def get_sla_start_date(self):
        if self.sla_start_date:
            return self.sla_start_date
        return self.date

    def get_sla_configuration(self):
        return self.test.engagement.product.sla_configuration

    def get_sla_period(self):
        # Determine which method to use to calculate the SLA
        from dojo.utils import get_custom_method  # noqa: PLC0415 -- lazy import, avoids circular dependency
        if method := get_custom_method("FINDING_SLA_PERIOD_METHOD"):
            return method(self)
        # Run the default method
        sla_configuration = self.get_sla_configuration()
        sla_period = getattr(sla_configuration, self.severity.lower(), None)
        enforce_period = getattr(sla_configuration, str("enforce_" + self.severity.lower()), None)
        return sla_period, enforce_period

    def set_sla_expiration_date(self):
        # First check if SLA is enabled globally
        from dojo.models import System_Settings  # noqa: PLC0415 -- lazy import, avoids circular dependency
        system_settings = System_Settings.objects.get()
        if not system_settings.enable_finding_sla:
            return
        # Call the internal method to set the sla expiration date
        self._set_sla_expiration_date()

    def _set_sla_expiration_date(self):
        # some parsers provide date as a `str` instead of a `date` in which case we need to parse it #12299 on GitHub
        sla_start_date = self.get_sla_start_date()
        if sla_start_date and isinstance(sla_start_date, str):
            sla_start_date = dateutil.parser.parse(sla_start_date).date()

        sla_period, enforce_period = self.get_sla_period()
        if sla_period is not None and enforce_period:
            self.sla_expiration_date = sla_start_date + relativedelta(days=sla_period)
        else:
            self.sla_expiration_date = None

    def sla_days_remaining(self):
        if self.sla_expiration_date:
            if self.mitigated:
                mitigated_date = self.mitigated
                if isinstance(mitigated_date, datetime):
                    mitigated_date = self.mitigated.date()
                return (self.sla_expiration_date - mitigated_date).days
            return (self.sla_expiration_date - get_current_date()).days
        return None

    def sla_deadline(self):
        return self.sla_expiration_date

    def github(self):
        from dojo.github.models import GITHUB_Issue  # noqa: PLC0415 -- lazy import, avoids circular dependency
        try:
            return self.github_issue
        except GITHUB_Issue.DoesNotExist:
            return None

    def has_github_issue(self):
        from dojo.github.models import GITHUB_Issue  # noqa: PLC0415 -- lazy import, avoids circular dependency
        try:
            # Attempt to access the github issue if it exists. If not, an exception will be caught
            _ = self.github_issue
        except GITHUB_Issue.DoesNotExist:
            return False
        return True

    def github_conf(self):
        from dojo.github.models import GITHUB_PKey  # noqa: PLC0415 -- lazy import, avoids circular dependency
        try:
            github_product_key = GITHUB_PKey.objects.get(product=self.test.engagement.product)
            github_conf = github_product_key.conf
        except:
            github_conf = None
        return github_conf

    # newer version that can work with prefetching
    def github_conf_new(self):
        try:
            return self.test.engagement.product.github_pkey_set.all()[0].git_conf
        except:
            return None

    @property
    def has_jira_issue(self):
        from dojo.jira import services as jira_services  # noqa: PLC0415 -- lazy import, avoids circular dependency
        return jira_services.has_issue(self)

    @cached_property
    def finding_group(self):
        return self.finding_group_set.all().first()
        # logger.debug('finding.finding_group: %s', group)

    @cached_property
    def has_jira_group_issue(self):
        if not self.has_finding_group:
            return False

        from dojo.jira import services as jira_services  # noqa: PLC0415 -- lazy import, avoids circular dependency
        return jira_services.has_issue(self.finding_group)

    @property
    def has_jira_configured(self):
        from dojo.jira import services as jira_services  # noqa: PLC0415 -- lazy import, avoids circular dependency
        return jira_services.has_configured(self)

    @cached_property
    def has_finding_group(self):
        return self.finding_group is not None

    def save_no_options(self, *args, **kwargs):
        logger.debug("save_no_options")
        return self.save(dedupe_option=False, rules_option=False, product_grading_option=False,
             issue_updater_option=False, push_to_jira=False, user=None, *args, **kwargs)

    # Check if a mandatory field is empty. If it's the case, fill it with "no <fieldName> given"
    def clean(self):
        no_check = ["test", "reporter"]
        bigfields = ["description"]
        for field_obj in self._meta.fields:
            field = field_obj.name
            if field not in no_check:
                val = getattr(self, field)
                if not val and field == "title":
                    setattr(self, field, "No title given")
                if not val and field in bigfields:
                    setattr(self, field, f"No {field} given")

    def severity_display(self):
        return self.severity

    def get_breadcrumbs(self):
        bc = self.test.get_breadcrumbs()
        bc += [{"title": str(self),
                "url": reverse("view_finding", args=(self.id,))}]
        return bc

    def get_valid_request_response_pairs(self):
        empty_value = base64.b64encode(b"")
        # Get a list of all req/resp pairs
        all_req_resps = self.burprawrequestresponse_set.all()
        # Filter away those that do not have any contents
        return all_req_resps.exclude(
            burpRequestBase64__exact=empty_value,
            burpResponseBase64__exact=empty_value,
        )

    def get_report_requests(self):
        # Get the list of request response pairs that are non empty
        request_response_pairs = self.get_valid_request_response_pairs()
        # Determine how many to return
        if request_response_pairs.count() >= 3:
            return request_response_pairs[0:3]
        if request_response_pairs.count() > 0:
            return request_response_pairs
        return None

    def get_request(self):
        # Get the list of request response pairs that are non empty
        request_response_pairs = self.get_valid_request_response_pairs()
        # Determine what to return
        if request_response_pairs.count() > 0:
            reqres = request_response_pairs.first()
        return base64.b64decode(reqres.burpRequestBase64)

    def get_response(self):
        # Get the list of request response pairs that are non empty
        request_response_pairs = self.get_valid_request_response_pairs()
        # Determine what to return
        if request_response_pairs.count() > 0:
            reqres = request_response_pairs.first()
        res = base64.b64decode(reqres.burpResponseBase64)
        # Removes all blank lines
        return re.sub(r"\n\s*\n", "\n", res)

    def latest_note(self):
        if self.notes.all():
            note = self.notes.all()[0]
            return note.date.strftime("%Y-%m-%d %H:%M:%S") + ": " + note.author.get_full_name() + " : " + note.entry

        return ""

    def get_sast_source_file_path_with_link(self):
        from dojo.utils import create_bleached_link  # noqa: PLC0415 -- lazy import, avoids circular dependency
        if self.sast_source_file_path is None:
            return None
        if self.test.engagement.source_code_management_uri is None:
            return escape(self.sast_source_file_path)
        link = self.test.engagement.source_code_management_uri + "/" + self.sast_source_file_path
        if self.sast_source_line:
            link = link + "#L" + str(self.sast_source_line)
        return create_bleached_link(link, self.sast_source_file_path)

    def get_file_path_with_link(self):
        from dojo.utils import create_bleached_link  # noqa: PLC0415 -- lazy import, avoids circular dependency
        if self.file_path is None:
            return None
        if self.test.engagement.source_code_management_uri is None:
            return escape(self.file_path)
        link = self.get_file_path_with_raw_link()
        return create_bleached_link(link, self.file_path)

    def get_scm_type(self):
        # extract scm type from product custom field 'scm-type'

        from dojo.models import DojoMeta  # noqa: PLC0415 -- lazy import, avoids circular dependency
        if hasattr(self.test.engagement, "product"):
            dojo_meta = DojoMeta.objects.filter(product=self.test.engagement.product, name="scm-type").first()
            if dojo_meta:
                st = dojo_meta.value.strip()
                if st:
                    return st.lower()
        return ""

    def scm_public_prepare_base_link(self, uri):
        # scm public (https://scm-domain.org) url template for browse is:
        # https://scm-domain.org/<username>/<repository-slug>
        # but when you get repo url for git, its template is:
        # https://scm-domain.org/<username>/<repository-slug>.git
        # so to create browser url - git url should be recomposed like below:

        parts_uri = uri.split(".git")
        return parts_uri[0]

    def git_public_prepare_scm_link(self, uri, scm_type):
        # if commit hash or branch/tag is set for engagement/test -
        # hash or branch/tag should be appended to base browser link
        intermediate_path = "/blob/" if scm_type in {"github", "gitlab"} else "/src/"

        link = self.scm_public_prepare_base_link(uri)
        if self.test.commit_hash:
            link += intermediate_path + self.test.commit_hash + "/" + self.file_path
        elif self.test.engagement.commit_hash:
            link += intermediate_path + self.test.engagement.commit_hash + "/" + self.file_path
        elif self.test.branch_tag:
            link += intermediate_path + self.test.branch_tag + "/" + self.file_path
        elif self.test.engagement.branch_tag:
            link += intermediate_path + self.test.engagement.branch_tag + "/" + self.file_path
        else:
            link += intermediate_path + "master/" + self.file_path

        return link

    def bitbucket_standalone_prepare_scm_base_link(self, uri):
        # bitbucket onpremise/standalone url template for browse is:
        # https://bb.example.com/projects/<project-key>/repos/<repository-slug>
        # but when you get repo url for git, its template is:
        # https://bb.example.com/scm/<project-key>/<repository-slug>.git
        # or for user public repo^
        # https://bb.example.com/users/<username>/repos/<repository-slug>
        # but when you get repo url for git, its template is:
        # https://bb.example.com/scm/<username>/<repository-slug>.git (username often could be prefixed with ~)
        # so to create borwser url - git url should be recomposed like below:

        parts_uri = uri.split(".git")
        parts_scm = parts_uri[0].split("/scm/")
        parts_project = parts_scm[1].split("/")
        project = parts_project[0]
        if project.startswith("~"):
            return parts_scm[0] + "/users/" + parts_project[0][1:] + "/repos/" + parts_project[1] + "/browse"
        return parts_scm[0] + "/projects/" + parts_project[0] + "/repos/" + parts_project[1] + "/browse"

    def bitbucket_standalone_prepare_scm_link(self, uri):
        # if commit hash or branch/tag is set for engagement/test -
        # hash or barnch/tag should be appended to base browser link

        link = self.bitbucket_standalone_prepare_scm_base_link(uri)
        if self.test.commit_hash:
            link += "/" + self.file_path + "?at=" + self.test.commit_hash
        elif self.test.engagement.commit_hash:
            link += "/" + self.file_path + "?at=" + self.test.engagement.commit_hash
        elif self.test.branch_tag:
            link += "/" + self.file_path + "?at=" + self.test.branch_tag
        elif self.test.engagement.branch_tag:
            link += "/" + self.file_path + "?at=" + self.test.engagement.branch_tag
        else:
            link += "/" + self.file_path

        return link

    def get_file_path_with_raw_link(self):
        if self.file_path is None:
            return None

        link = self.test.engagement.source_code_management_uri
        scm_type = self.get_scm_type()
        if (self.test.engagement.source_code_management_uri is not None):
            if scm_type == "bitbucket-standalone":
                link = self.bitbucket_standalone_prepare_scm_link(link)
            elif scm_type in {"github", "gitlab", "gitea", "codeberg", "bitbucket"}:
                link = self.git_public_prepare_scm_link(link, scm_type)
            elif "https://github.com/" in self.test.engagement.source_code_management_uri:
                link = self.git_public_prepare_scm_link(link, "github")
            else:
                link += "/" + self.file_path
        else:
            link += "/" + self.file_path

        # than - add line part to browser url
        if self.line:
            if scm_type in {"github", "gitlab", "gitea", "codeberg"} or "https://github.com/" in self.test.engagement.source_code_management_uri:
                link = link + "#L" + str(self.line)
            elif scm_type == "bitbucket-standalone":
                link = link + "#" + str(self.line)
            elif scm_type == "bitbucket":
                link = link + "#lines-" + str(self.line)
        return link

    def get_references_with_links(self):
        from dojo.utils import create_bleached_link  # noqa: PLC0415 -- lazy import, avoids circular dependency
        if self.references is None:
            return None
        matches = re.findall(r"([\(|\[]?(https?):((//)|(\\\\))+([\w\d:#@%/;$~_?\+-=\\\.&](#!)?)*[\)|\]]?)", self.references)

        processed_matches = []
        for match in matches:
            # Check if match isn't already a markdown link
            # Only replace the same matches one time, otherwise the links will be corrupted
            if not (match[0].startswith("[") or match[0].startswith("(")) and match[0] not in processed_matches:
                self.references = self.references.replace(match[0], create_bleached_link(match[0], match[0]), 1)
                processed_matches.append(match[0])

        return self.references

    @cached_property
    def vulnerability_ids(self):
        # Get vulnerability ids from database and convert to list of strings
        vulnerability_ids_model = self.vulnerability_id_set.all()
        vulnerability_ids = [vulnerability_id.vulnerability_id for vulnerability_id in vulnerability_ids_model]

        # Synchronize the cve field with the unsaved_vulnerability_ids
        # We do this to be as flexible as possible to handle the fields until
        # the cve field is not needed anymore and can be removed.
        if vulnerability_ids and self.cve:
            # Make sure the first entry of the list is the value of the cve field
            vulnerability_ids.insert(0, self.cve)
        elif not vulnerability_ids and self.cve:
            # If there is no list, make one with the value of the cve field
            vulnerability_ids = [self.cve]

        # Remove duplicates
        return list(dict.fromkeys(vulnerability_ids))

    @property
    def violates_sla(self):
        return (self.sla_expiration_date and self.sla_expiration_date < timezone.now().date())

    def set_hash_code(self, dedupe_option):
        from dojo.utils import get_custom_method  # noqa: PLC0415 -- lazy import, avoids circular dependency
        if hash_method := get_custom_method("FINDING_HASH_METHOD"):
            deduplicationLogger.debug("Using custom hash method")
            hash_method(self, dedupe_option)
        # Finding.save is called once from serializers.py with dedupe_option=False because the finding is not ready yet, for example the endpoints are not built
        # It is then called a second time with dedupe_option defaulted to true; now we can compute the hash_code and run the deduplication
        elif dedupe_option:
            finding_id = self.id if self.id is not None else "unsaved"
            if self.hash_code is not None:
                deduplicationLogger.debug("Hash_code already computed for finding: %s", finding_id)
            else:
                self.hash_code = self.compute_hash_code()
                deduplicationLogger.debug("Hash_code computed for finding: %s: %s", finding_id, self.hash_code)


class Vulnerability_Id(models.Model):
    finding = models.ForeignKey("dojo.Finding", editable=False, on_delete=models.CASCADE)
    vulnerability_id = models.TextField(max_length=50, blank=False, null=False)

    def __str__(self):
        return self.vulnerability_id

    def get_absolute_url(self):
        return reverse("view_finding", args=[str(self.finding.id)])


class Finding_Group(TimeStampedModel):

    GROUP_BY_OPTIONS = [("component_name", "Component Name"),
                        ("component_name+component_version", "Component Name + Version"),
                        ("file_path", "File path"),
                        ("finding_title", "Finding Title"),
                        ("vuln_id_from_tool", "Vulnerability ID from Tool")]

    name = models.CharField(max_length=255, blank=False, null=False)
    test = models.ForeignKey("dojo.Test", on_delete=models.CASCADE)
    findings = models.ManyToManyField("dojo.Finding")
    creator = models.ForeignKey("dojo.Dojo_User", on_delete=models.RESTRICT)

    def __str__(self):
        return self.name

    @property
    def has_jira_issue(self):
        from dojo.jira import services as jira_services  # noqa: PLC0415 -- lazy import, avoids circular dependency
        return jira_services.has_issue(self)

    @cached_property
    def severity(self):
        if not self.findings.all():
            return None
        max_number_severity = max(Finding.get_number_severity(find.severity) for find in self.findings.all())
        return Finding.get_severity(max_number_severity)

    @cached_property
    def components(self):
        components: dict[str, set[str | None]] = {}
        for finding in self.findings.all():
            if finding.component_name is not None:
                components.setdefault(finding.component_name, set()).add(finding.component_version)
        return "; ".join(f"""{name}: {", ".join(map(str, versions))}""" for name, versions in components.items())

    @property
    def age(self):
        if not self.findings.all():
            return None

        return max(find.age for find in self.findings.all())

    @cached_property
    def sla_days_remaining_internal(self):
        if not self.findings.all():
            return None

        return min([find.sla_days_remaining() for find in self.findings.all() if find.sla_days_remaining()], default=None)

    def sla_days_remaining(self):
        return self.sla_days_remaining_internal

    def sla_deadline(self):
        if not self.findings.all():
            return None

        return min([find.sla_deadline() for find in self.findings.all() if find.sla_deadline()], default=None)

    def status(self):
        if not self.findings.all():
            return None

        if any(find.active for find in self.findings.all()):
            return "Active"

        if all(find.is_mitigated for find in self.findings.all()):
            return "Mitigated"

        return "Inactive"

    @cached_property
    def mitigated(self):
        return all(find.mitigated is not None for find in self.findings.all())

    def get_sla_start_date(self):
        return min(find.get_sla_start_date() for find in self.findings.all())

    def get_absolute_url(self):
        return reverse("view_test", args=[str(self.test.id)])

    class Meta:
        ordering = ["id"]


class Finding_Template(models.Model):
    title = models.TextField(max_length=1000)
    cwe = models.IntegerField(default=None, null=True, blank=True)
    cve = models.CharField(max_length=50,
                           null=True,
                           blank=False,
                           verbose_name="Vulnerability Id",
                           help_text="An id of a vulnerability in a security advisory associated with this finding. Can be a Common Vulnerabilities and Exposures (CVE) or from other sources.")
    cvssv3 = models.TextField(help_text=_("Common Vulnerability Scoring System version 3 (CVSSv3) score associated with this finding."), validators=[cvss3_validator], max_length=117, null=True, verbose_name=_("CVSS v3 vector"))
    cvssv3_score = models.FloatField(null=True, blank=True, help_text=_("CVSSv3 score"))
    cvssv4 = models.TextField(help_text=_("Common Vulnerability Scoring System version 4 (CVSS4) score associated with this finding."), validators=[cvss4_validator], max_length=255, null=True, verbose_name=_("CVSS4 vector"))
    cvssv4_score = models.FloatField(null=True, blank=True, help_text=_("CVSSv4 score"))

    severity = models.CharField(max_length=200, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    mitigation = models.TextField(null=True, blank=True)
    impact = models.TextField(null=True, blank=True)
    references = models.TextField(null=True, blank=True, db_column="refs")
    last_used = models.DateTimeField(null=True, editable=False)
    numerical_severity = models.CharField(max_length=4, null=True, blank=True, editable=False)

    # Remediation planning fields
    fix_available = models.BooleanField(null=True, blank=True, help_text=_("Indicates if a fix is available for this vulnerability type"))
    fix_version = models.CharField(max_length=100, null=True, blank=True, help_text=_("Version where fix is available"))
    planned_remediation_version = models.CharField(max_length=99, null=True, blank=True, help_text=_("Target version for remediation"))
    effort_for_fixing = models.CharField(max_length=99, null=True, blank=True, help_text=_("Effort estimate for fixing (e.g., Low/Medium/High)"))

    # Technical details fields
    steps_to_reproduce = models.TextField(null=True, blank=True, help_text=_("Standard reproduction steps for this vulnerability type"))
    severity_justification = models.TextField(null=True, blank=True, help_text=_("Explanation of why this severity level is appropriate"))
    component_name = models.CharField(max_length=500, null=True, blank=True, help_text=_("Affected component name (e.g., library name)"))
    component_version = models.CharField(max_length=100, null=True, blank=True, help_text=_("Affected component version"))

    # Notes field (single note content, not a list)
    notes = models.TextField(null=True, blank=True, help_text=_("Note content to add when applying this template"))

    # String-based list fields (newline-separated)
    vulnerability_ids_text = models.TextField(null=True, blank=True, help_text=_("Vulnerability IDs (one per line)"))
    endpoints_text = models.TextField(null=True, blank=True, help_text=_("Endpoint URLs (one per line)"))

    tags = TagField(blank=True, force_lowercase=True, help_text=_("Add tags that help describe this finding template. Choose from the list or add new tags. Press Enter key to add."))

    SEVERITIES = {"Info": 4, "Low": 3, "Medium": 2,
                  "High": 1, "Critical": 0}

    class Meta:
        ordering = ["-cwe"]

    def __str__(self):
        return self.title

    def get_absolute_url(self):
        return reverse("edit_template", args=[str(self.id)])

    def get_breadcrumbs(self):
        return [{"title": str(self),
               "url": reverse("view_template", args=(self.id,))}]

    @property
    def vulnerability_ids(self):
        """Parse vulnerability IDs from TextField string (newline-separated)."""
        vulnerability_ids = []

        # Get from the TextField
        if self.vulnerability_ids_text:
            # Parse newline-separated string, remove empty lines
            vulnerability_ids = [line.strip() for line in self.vulnerability_ids_text.split("\n") if line.strip()]

        # Synchronize the cve field with the vulnerability_ids
        # We do this to be as flexible as possible to handle the fields until
        # the cve field is not needed anymore and can be removed.
        if vulnerability_ids and self.cve and self.cve not in vulnerability_ids:
            # Make sure the first entry of the list is the value of the cve field
            vulnerability_ids.insert(0, self.cve)
        elif not vulnerability_ids and self.cve:
            # If there is no list, make one with the value of the cve field
            vulnerability_ids = [self.cve]

        # Remove duplicates
        return list(dict.fromkeys(vulnerability_ids))

    @property
    def endpoints(self):
        """Parse endpoint URLs from TextField string (newline-separated)."""
        if not self.endpoints_text:
            return []
        # Parse newline-separated string, remove empty lines
        return [line.strip() for line in self.endpoints_text.split("\n") if line.strip()]


class CWE(models.Model):
    url = models.CharField(max_length=1000)
    description = models.CharField(max_length=2000)
    number = models.IntegerField()


class BurpRawRequestResponse(models.Model):
    finding = models.ForeignKey("dojo.Finding", blank=True, null=True, on_delete=models.CASCADE)
    burpRequestBase64 = models.BinaryField()
    burpResponseBase64 = models.BinaryField()

    def get_request(self):
        return str(base64.b64decode(self.burpRequestBase64), errors="ignore")

    def get_response(self):
        res = str(base64.b64decode(self.burpResponseBase64), errors="ignore")
        # Removes all blank lines
        return re.sub(r"\n\s*\n", "\n", res)
