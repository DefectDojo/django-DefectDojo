import base64
import contextlib
import copy
import logging
import re
import warnings
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

import hyperlink
import tagulous.admin
from django import forms
from django.conf import settings
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.validators import MaxValueValidator, MinValueValidator, RegexValidator, validate_ipv46_address
from django.db import connection, models
from django.db.models import Count, F, Q
from django.db.models.expressions import Case, When
from django.db.models.functions import Lower
from django.urls import reverse
from django.utils import timezone
from django.utils.deconstruct import deconstructible
from django.utils.timezone import now
from django.utils.translation import gettext as _
from django_extensions.db.models import TimeStampedModel
from polymorphic.base import ManagerInheritanceWarning
from polymorphic.managers import PolymorphicManager
from polymorphic.models import PolymorphicModel
from tagulous.models import TagField
from tagulous.models.managers import FakeTagRelatedManager  # noqa: F401 -- backward compat re-export

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")

SEVERITY_CHOICES = (("Info", "Info"), ("Low", "Low"), ("Medium", "Medium"),
                    ("High", "High"), ("Critical", "Critical"))

SEVERITIES = [s[0] for s in SEVERITY_CHOICES]

EFFORT_FOR_FIXING_CHOICES = (("", ""), ("Low", "Low"), ("Medium", "Medium"), ("High", "High"))

# fields returned in statistics, typically all status fields
STATS_FIELDS = ["active", "verified", "duplicate", "false_p", "out_of_scope", "is_mitigated", "risk_accepted", "total"]
# default template with all values set to 0
DEFAULT_STATS = {sev.lower(): dict.fromkeys(STATS_FIELDS, 0) for sev in SEVERITIES}


def _get_annotations_for_statistics():
    annotations = {stats_field.lower(): Count(Case(When(**{stats_field: True}, then=1))) for stats_field in STATS_FIELDS if stats_field != "total"}
    # add total
    annotations["total"] = Count("id")
    return annotations


def _get_statistics_for_queryset(qs, annotation_factory):
    # order by to get rid of default ordering that would mess with group_by
    # group by severity (lowercase)
    values = qs.annotate(sev=Lower("severity")).values("sev").order_by()
    # add annotation for each status field
    values = values.annotate(**annotation_factory())
    # make sure sev and total are included
    stat_fields = ["sev", "total", *STATS_FIELDS]
    # go for it
    values = values.values(*stat_fields)

    # not sure if there's a smarter way to convert a list of dicts into a dict of dicts
    # need to copy the DEFAULT_STATS otherwise it gets overwritten
    stats = copy.copy(DEFAULT_STATS)
    for row in values:
        sev = row.pop("sev")
        stats[sev] = row

    values_total = qs.values()
    values_total = values_total.aggregate(**annotation_factory())
    stats["total"] = values_total
    return stats


def _sync_inherited_tags(obj, incoming_inherited_tags):
    # Backward-compat shim. Implementation lives in dojo.tags.inheritance; lazy
    # import keeps dojo.models loadable before dojo.tags.inheritance (which
    # transitively imports dojo.utils -> dojo.models) is ready.
    from dojo.tags.inheritance import _sync_inherited_tags as _impl  # noqa: PLC0415
    return _impl(obj, incoming_inherited_tags)


def copy_model_util(model_in_database, exclude_fields: list[str] | None = None):
    if exclude_fields is None:
        exclude_fields = []
    new_model_instance = model_in_database.__class__()
    for field in model_in_database._meta.fields:
        if field.name not in {"id", *exclude_fields}:
            setattr(new_model_instance, field.name, getattr(model_in_database, field.name))
    return new_model_instance


def tomorrow():
    """Returns a date representing the day after today."""
    return timezone.now().date() + timedelta(days=1)


@deconstructible
class UniqueUploadNameProvider:

    """
    A callable to be passed as upload_to parameter to FileField.

    Uploaded files will get random names based on UUIDs inside the given directory;
    strftime-style formatting is supported within the directory path. If keep_basename
    is True, the original file name is prepended to the UUID. If keep_ext is disabled,
    the filename extension will be dropped.
    """

    def __init__(self, directory=None, *, keep_basename=False, keep_ext=True):
        self.directory = directory
        self.keep_basename = keep_basename
        self.keep_ext = keep_ext

    def __call__(self, model_instance, filename):
        path = Path(filename)
        base = path.parent / path.stem
        ext = path.suffix
        filename = f"{base}_{uuid4()}" if self.keep_basename else str(uuid4())
        if self.keep_ext:
            filename += ext
        if self.directory is None:
            return filename
        return Path(now().strftime(self.directory)) / filename


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


User = get_user_model()


# proxy class for convenience and UI
class Dojo_User(User):
    class Meta:
        proxy = True
        ordering = ["first_name"]

    def get_full_name(self):
        return Dojo_User.generate_full_name(self)

    def __str__(self):
        return self.get_full_name()

    @staticmethod
    def wants_block_execution(user):
        # this return False if there is no user, i.e. in celery processes, unittests, etc.
        return hasattr(user, "usercontactinfo") and user.usercontactinfo.block_execution

    @staticmethod
    def force_password_reset(user):
        return hasattr(user, "usercontactinfo") and user.usercontactinfo.force_password_reset

    def disable_force_password_reset(self):
        if hasattr(self, "usercontactinfo"):
            self.usercontactinfo.force_password_reset = False
            self.usercontactinfo.save()

    def enable_force_password_reset(self):
        if hasattr(self, "usercontactinfo"):
            self.usercontactinfo.force_password_reset = True
            self.usercontactinfo.save()

    @staticmethod
    def generate_full_name(user):
        """Returns the first_name plus the last_name, with a space in between."""
        full_name = f"{user.first_name} {user.last_name} ({user.username})"
        return full_name.strip()


class UserContactInfo(models.Model):
    user = models.OneToOneField(Dojo_User, on_delete=models.CASCADE)
    title = models.CharField(blank=True, null=True, max_length=150)
    phone_regex = RegexValidator(regex=r"^\+?1?\d{9,15}$",
                                 message=_("Phone number must be entered in the format: '+999999999'. "
                                         "Up to 15 digits allowed."))
    phone_number = models.CharField(validators=[phone_regex], blank=True,
                                    max_length=15,
                                    help_text=_("Phone number must be entered in the format: '+999999999'. "
                                              "Up to 15 digits allowed."))
    cell_number = models.CharField(validators=[phone_regex], blank=True,
                                   max_length=15,
                                   help_text=_("Phone number must be entered in the format: '+999999999'. "
                                             "Up to 15 digits allowed."))
    twitter_username = models.CharField(blank=True, null=True, max_length=150)
    github_username = models.CharField(blank=True, null=True, max_length=150)
    slack_username = models.CharField(blank=True, null=True, max_length=150, help_text=_("Email address associated with your slack account"), verbose_name=_("Slack Email Address"))
    slack_user_id = models.CharField(blank=True, null=True, max_length=25)
    block_execution = models.BooleanField(default=False, help_text=_("Instead of async deduping a finding the findings will be deduped synchronously and will 'block' the user until completion."))
    force_password_reset = models.BooleanField(default=False, help_text=_("Forces this user to reset their password on next login."))
    ui_use_tailwind = models.BooleanField(default=False, verbose_name=_("Use new UI (beta)"), help_text=_("Opt in to the new Tailwind-based UI. Leave off for the classic UI."))
    token_last_reset = models.DateTimeField(null=True, blank=True, help_text=_("Timestamp of the most recent API token reset for this user."))
    password_last_reset = models.DateTimeField(null=True, blank=True, help_text=_("Timestamp of the most recent password reset for this user."))


class System_Settings(models.Model):
    enable_deduplication = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Deduplicate findings"),
        help_text=_("With this setting turned on, DefectDojo deduplicates findings by "
                  "comparing endpoints, cwe fields, and titles. "
                  "If two findings share a URL and have the same CWE or "
                  "title, DefectDojo marks the recent finding as a duplicate. "
                  "When deduplication is enabled, a list of "
                  "deduplicated findings is added to the engagement view."))
    delete_duplicates = models.BooleanField(default=False, blank=False, help_text=_("Requires next setting: maximum number of duplicates to retain."))
    max_dupes = models.IntegerField(blank=True, null=True, default=10,
                                    verbose_name=_("Max Duplicates"),
                                    help_text=_("When enabled, if a single "
                                              "issue reaches the maximum "
                                              "number of duplicates, the "
                                              "oldest will be deleted. Duplicate will not be deleted when left empty. A value of 0 will remove all duplicates."))

    email_from = models.CharField(max_length=200, default="no-reply@example.com", blank=True)

    enable_jira = models.BooleanField(default=False,
                                      verbose_name=_("Enable JIRA integration"),
                                      blank=False)

    enable_jira_web_hook = models.BooleanField(default=False,
                                      verbose_name=_("Enable JIRA web hook"),
                                      help_text=_("Please note: It is strongly recommended to use a secret below and / or IP whitelist the JIRA server using a proxy such as Nginx."),
                                      blank=False)

    disable_jira_webhook_secret = models.BooleanField(default=False,
                                      verbose_name=_("Disable web hook secret"),
                                      help_text=_("Allows incoming requests without a secret (discouraged legacy behaviour)"),
                                      blank=False)

    # will be set to random / uuid by initializer so null needs to be True
    jira_webhook_secret = models.CharField(max_length=64, blank=False, null=True, verbose_name=_("JIRA Webhook URL"),
                                           help_text=_("Secret needed in URL for incoming JIRA Webhook"))

    jira_choices = (("Critical", "Critical"),
                    ("High", "High"),
                    ("Medium", "Medium"),
                    ("Low", "Low"),
                    ("Info", "Info"))
    jira_minimum_severity = models.CharField(max_length=20, blank=True,
                                             null=True, choices=jira_choices,
                                             default="Low")
    jira_labels = models.CharField(max_length=200, blank=True, null=True,
                                   help_text=_("JIRA issue labels space seperated"))

    add_vulnerability_id_to_jira_label = models.BooleanField(default=False,
                                        verbose_name=_("Add vulnerability Id as a JIRA label"),
                                        blank=False)

    enable_github = models.BooleanField(default=False,
                                      verbose_name=_("Enable GITHUB integration"),
                                      blank=False)

    enable_slack_notifications = \
        models.BooleanField(default=False,
                            verbose_name=_("Enable Slack notifications"),
                            blank=False)
    slack_channel = models.CharField(max_length=100, default="", blank=True,
                    help_text=_("Optional. Needed if you want to send global notifications."))
    slack_token = models.CharField(max_length=100, default="", blank=True,
                                   help_text=_("Token required for interacting "
                                             "with Slack. Get one at "
                                             "https://api.slack.com/tokens"))
    slack_username = models.CharField(max_length=100, default="", blank=True,
                     help_text=_("Optional. Will take your bot name otherwise."))
    enable_msteams_notifications = \
        models.BooleanField(default=False,
                            verbose_name=_("Enable Microsoft Teams notifications"),
                            blank=False)
    msteams_url = models.CharField(max_length=400, default="", blank=True,
                                    help_text=_("The full URL of the "
                                              "incoming webhook"))
    enable_mail_notifications = models.BooleanField(default=False, blank=False)
    mail_notifications_to = models.CharField(max_length=200, default="",
                                             blank=True)

    enable_webhooks_notifications = \
        models.BooleanField(default=False,
                            verbose_name=_("Enable Webhook notifications"),
                            blank=False)
    webhooks_notifications_timeout = models.IntegerField(default=10,
                                          help_text=_("How many seconds will DefectDojo waits for response from webhook endpoint"))

    enforce_verified_status = models.BooleanField(
        default=True,
        verbose_name=_("Enforce Verified Status - Globally"),
        help_text=_(
            "When enabled, features such as product grading, jira "
            "integration, metrics, and reports will only interact "
            "with verified findings. This setting will override "
            "individually scoped verified toggles.",
        ),
    )
    enforce_verified_status_jira = models.BooleanField(
        default=True,
        verbose_name=_("Enforce Verified Status - Jira"),
        help_text=_("When enabled, findings must have a verified status to be pushed to jira."),
    )
    enforce_verified_status_product_grading = models.BooleanField(
        default=True,
        verbose_name=_("Enforce Verified Status - Product Grading"),
        help_text=_(
            "When enabled, findings must have a verified status to be considered as part of a product's grading.",
        ),
    )
    enforce_verified_status_metrics = models.BooleanField(
        default=True,
        verbose_name=_("Enforce Verified Status - Metrics"),
        help_text=_(
            "When enabled, findings must have a verified status to be counted in metric calculations, "
            "be included in reports, and filters.",
        ),
    )

    false_positive_history = models.BooleanField(
        default=False, help_text=_(
            "(EXPERIMENTAL) DefectDojo will automatically mark the finding as a "
            "false positive if an equal finding (according to its dedupe algorithm) "
            "has been previously marked as a false positive on the same product. "
            "ATTENTION: Although the deduplication algorithm is used to determine "
            "if a finding should be marked as a false positive, this feature will "
            "not work if deduplication is enabled since it doesn't make sense to use both.",
        ),
    )

    retroactive_false_positive_history = models.BooleanField(
        default=False, help_text=_(
            "(EXPERIMENTAL) FP History will also retroactively mark/unmark all "
            "existing equal findings in the same product as a false positives. "
            "Only works if the False Positive History feature is also enabled.",
        ),
    )

    url_prefix = models.CharField(max_length=300, default="", blank=True, help_text=_("URL prefix if DefectDojo is installed in it's own virtual subdirectory."))
    team_name = models.CharField(max_length=100, default="", blank=True)
    enable_product_grade = models.BooleanField(default=False, verbose_name=_("Enable Product Grading"), help_text=_("Displays a grade letter next to a product to show the overall health."))
    product_grade_a = models.IntegerField(default=90,
                                          verbose_name=_("Grade A"),
                                          help_text=_("Percentage score for an "
                                                    "'A' >="))
    product_grade_b = models.IntegerField(default=80,
                                          verbose_name=_("Grade B"),
                                          help_text=_("Percentage score for a "
                                                    "'B' >="))
    product_grade_c = models.IntegerField(default=70,
                                          verbose_name=_("Grade C"),
                                          help_text=_("Percentage score for a "
                                                    "'C' >="))
    product_grade_d = models.IntegerField(default=60,
                                          verbose_name=_("Grade D"),
                                          help_text=_("Percentage score for a "
                                                    "'D' >="))
    product_grade_f = models.IntegerField(default=59,
                                          verbose_name=_("Grade F"),
                                          help_text=_("Percentage score for an "
                                                    "'F' <="))
    enable_product_tag_inheritance = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Enable Product Tag Inheritance"),
        help_text=_("Enables product tag inheritance globally for all products. Any tags added on a product will automatically be added to all Engagements, Tests, and Findings"))

    enable_benchmark = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable Benchmarks"),
        help_text=_("Enables Benchmarks such as the OWASP ASVS "
                  "(Application Security Verification Standard)"))

    enable_similar_findings = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable Similar Findings"),
        help_text=_("Enable the query of similar findings on the view finding page. This feature can involve potentially large queries and negatively impact performance"))

    engagement_auto_close = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Enable Engagement Auto-Close"),
        help_text=_("Closes an engagement after 3 days (default) past due date including last update."))

    engagement_auto_close_days = models.IntegerField(
        default=3,
        blank=False,
        verbose_name=_("Engagement Auto-Close Days"),
        help_text=_("Closes an engagement after the specified number of days past due date including last update."))

    enable_finding_sla = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable Finding SLA's"),
        help_text=_("Enables Finding SLA's for time to remediate."))

    enable_notify_sla_active = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Enable Notify SLA's Breach for active Findings"),
        help_text=_("Enables Notify when time to remediate according to Finding SLA's is breached for active Findings."))

    enable_notify_sla_active_verified = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Enable Notify SLA's Breach for active, verified Findings"),
        help_text=_("Enables Notify when time to remediate according to Finding SLA's is breached for active, verified Findings."))

    enable_notify_sla_jira_only = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Enable Notify SLA's Breach only for Findings linked to JIRA"),
        help_text=_("Enables Notify when time to remediate according to Finding SLA's is breached for Findings that are linked to JIRA issues. Notification is disabled for Findings not linked to JIRA issues"))

    enable_notify_sla_exponential_backoff = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Enable an exponential backoff strategy for SLA breach notifications."),
        help_text=_("Enable an exponential backoff strategy for SLA breach notifications, e.g. 1, 2, 4, 8, etc. Otherwise it alerts every day"))

    allow_anonymous_survey_repsonse = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Allow Anonymous Survey Responses"),
        help_text=_("Enable anyone with a link to the survey to answer a survey"),
    )
    disclaimer_notifications = models.TextField(max_length=3000, default="", blank=True,
                                  verbose_name=_("Custom Disclaimer for Notifications"),
                                  help_text=_("Include this custom disclaimer on all notifications"))
    disclaimer_reports = models.TextField(max_length=5000, default="", blank=True,
                                  verbose_name=_("Custom Disclaimer for Reports"),
                                  help_text=_("Include this custom disclaimer on generated reports"))
    disclaimer_reports_forced = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Force to add disclaimer reports"),
        help_text=_("Disclaimer will be added to all reports even if user didn't selected 'Include disclaimer'."))
    disclaimer_notes = models.TextField(max_length=3000, default="", blank=True,
                                  verbose_name=_("Custom Disclaimer for Notes"),
                                  help_text=_("Include this custom disclaimer next to input form for notes"))
    risk_acceptance_form_default_days = models.IntegerField(null=True, blank=True, default=180, help_text=_("Default expiry period for risk acceptance form."))
    risk_acceptance_notify_before_expiration = models.IntegerField(null=True, blank=True, default=10,
                    verbose_name=_("Risk acceptance expiration heads up days"), help_text=_("Notify X days before risk acceptance expires. Leave empty to disable."))
    enable_questionnaires = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable questionnaires"),
        help_text=_("With this setting turned off, questionnaires will be disabled in the user interface."))
    enable_checklists = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable checklists"),
        help_text=_("With this setting turned off, checklists will be disabled in the user interface."))
    enable_endpoint_metadata_import = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable Endpoint Metadata Import"),
        help_text=_("With this setting turned off, endpoint metadata import will be disabled in the user interface."))
    enable_user_profile_editable = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable user profile for writing"),
        help_text=_("When turned on users can edit their profiles"))
    enable_product_tracking_files = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable Product Tracking Files"),
        help_text=_("With this setting turned off, the product tracking files will be disabled in the user interface."))
    enable_finding_groups = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable Finding Groups"),
        help_text=_("With this setting turned off, the Finding Groups will be disabled."))
    enable_ui_table_based_searching = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable UI Table Based Filtering/Sorting"),
        help_text=_("With this setting enabled, table headings will contain sort buttons for the current page of data in addition to sorting buttons that consider data from all pages."))
    enable_calendar = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable Calendar"),
        help_text=_("With this setting turned off, the Calendar will be disabled in the user interface."))
    enable_cvss3_display = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable CVSS3 Display"),
        help_text=_("With this setting turned off, CVSS3 fields will be hidden in the user interface."))
    enable_cvss4_display = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Enable CVSS4 Display"),
        help_text=_("With this setting turned off, CVSS4 fields will be hidden in the user interface."))
    minimum_password_length = models.IntegerField(
        default=9,
        verbose_name=_("Minimum password length"),
        help_text=_("Requires user to set passwords greater than minimum length."),
        validators=[MinValueValidator(9), MaxValueValidator(48)])
    maximum_password_length = models.IntegerField(
        default=48,
        verbose_name=_("Maximum password length"),
        help_text=_("Requires user to set passwords less than maximum length."),
        validators=[MinValueValidator(9), MaxValueValidator(48)])
    number_character_required = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Password must contain one digit"),
        help_text=_("Requires user passwords to contain at least one digit (0-9)."))
    special_character_required = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Password must contain one special character"),
        help_text=_("Requires user passwords to contain at least one special character (()[]{}|\\`~!@#$%^&*_-+=;:'\",<>./?)."))
    lowercase_character_required = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Password must contain one lowercase letter"),
        help_text=_("Requires user passwords to contain at least one lowercase letter (a-z)."))
    uppercase_character_required = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Password must contain one uppercase letter"),
        help_text=_("Requires user passwords to contain at least one uppercase letter (A-Z)."))
    non_common_password_required = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Password must not be common"),
        help_text=_("Requires user passwords to not be part of list of common passwords."))
    api_expose_error_details = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("API expose error details"),
        help_text=_("When turned on, the API will expose error details in the response."))
    filter_string_matching = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Filter String Matching Optimization"),
        help_text=_(
            "When turned on, all filter operations in the UI will require string matches rather than ID. "
            "This is a performance enhancement to avoid fetching objects unnecessarily.",
        ))

    from dojo.middleware import System_Settings_Manager  # noqa: PLC0415 circular import
    objects = System_Settings_Manager()

    def clean(self):
        super().clean()

        if (
            self.minimum_password_length is not None
            and self.maximum_password_length is not None
        ):
            if self.minimum_password_length > self.maximum_password_length:
                msg = "Minimum required password length must be larger than the maximum required password length."
                raise ValidationError({
                    "minimum_password_length": msg,
                })


def get_current_date():
    return timezone.now().date()


def get_current_datetime():
    return timezone.now()


class Contact(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    team = models.CharField(max_length=100)
    is_admin = models.BooleanField(default=False)
    is_globally_read_only = models.BooleanField(default=False)
    updated = models.DateTimeField(auto_now=True)


class Note_Type(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.CharField(max_length=200)
    is_single = models.BooleanField(default=False, null=False)
    is_active = models.BooleanField(default=True, null=False)
    is_mandatory = models.BooleanField(default=True, null=False)

    def __str__(self):
        return self.name


class NoteHistory(models.Model):
    note_type = models.ForeignKey(Note_Type, null=True, blank=True, on_delete=models.CASCADE)
    data = models.TextField()
    time = models.DateTimeField(null=True, editable=False,
                                default=get_current_datetime)
    current_editor = models.ForeignKey(Dojo_User, editable=False, null=True, on_delete=models.CASCADE)

    def copy(self):
        copy = copy_model_util(self)
        copy.save()
        return copy


class Notes(models.Model):
    note_type = models.ForeignKey(Note_Type, related_name="note_type", null=True, blank=True, on_delete=models.CASCADE)
    entry = models.TextField()
    date = models.DateTimeField(null=False, editable=False,
                                default=get_current_datetime)
    author = models.ForeignKey(Dojo_User, related_name="editor_notes_set", editable=False, on_delete=models.CASCADE)
    private = models.BooleanField(default=False)
    edited = models.BooleanField(default=False)
    editor = models.ForeignKey(Dojo_User, related_name="author_notes_set", editable=False, null=True, on_delete=models.CASCADE)
    edit_time = models.DateTimeField(null=True, editable=False,
                                default=get_current_datetime)
    history = models.ManyToManyField(NoteHistory, blank=True,
                                   editable=False)

    class Meta:
        ordering = ["-date"]

    def __str__(self):
        return self.entry

    def copy(self):
        copy = copy_model_util(self)
        # Save the necessary ManyToMany relationships
        old_history = list(self.history.all())
        # Save the object before setting any ManyToMany relationships
        copy.save()
        # Copy the history
        for history in old_history:
            copy.history.add(history.copy())

        return copy


class FileUpload(models.Model):
    title = models.CharField(max_length=100, unique=True)
    file = models.FileField(upload_to=UniqueUploadNameProvider("uploaded_files"))

    def delete(self, *args, **kwargs):
        """Delete the model and remove the file from storage."""
        storage = self.file.storage
        path = self.file.path
        super().delete(*args, **kwargs)
        if path and storage.exists(path):
            storage.delete(path)

    def copy(self):
        copy = copy_model_util(self)
        # Add unique modifier to file name
        # Truncate title to ensure it doesn't exceed max_length (100) when appending suffix
        # Suffix " - clone-{8 chars}" is 17 characters, so truncate to 83 chars
        clone_suffix = f" - clone-{str(uuid4())[:8]}"
        max_title_length = 100 - len(clone_suffix)
        truncated_title = self.title[:max_title_length] if len(self.title) > max_title_length else self.title
        copy.title = f"{truncated_title}{clone_suffix}"
        # Create new unique file name
        current_url = self.file.url
        _, current_full_filename = current_url.rsplit("/", 1)
        _, extension = current_full_filename.split(".", 1)
        new_file = ContentFile(self.file.read(), name=f"{uuid4()}.{extension}")
        copy.file = new_file
        copy.save()

        return copy

    def get_accessible_url(self, obj, obj_id):
        if isinstance(obj, Engagement):
            obj_type = "Engagement"
        elif isinstance(obj, Test):
            obj_type = "Test"
        elif isinstance(obj, Finding):
            obj_type = "Finding"

        return f"access_file/{self.id}/{obj_id}/{obj_type}"

    def clean(self):
        if not self.title:
            self.title = "<No Title>"

        valid_extensions = settings.FILE_UPLOAD_TYPES

        # why does this not work with self.file....
        file_name = self.file.url if self.file else self.title
        if Path(file_name).suffix.lower() not in valid_extensions:
            if accepted_extensions := f"{', '.join(valid_extensions)}":
                msg = (
                    _("Unsupported extension. Supported extensions are as follows: %s") % accepted_extensions
                )
            else:
                msg = (
                    _("File uploads are prohibited due to the list of acceptable file extensions being empty")
                )
            raise ValidationError(msg)


from dojo.product.models import (  # noqa: E402 -- re-export; class-body FKs below reference these
    Product,
    Product_API_Scan_Configuration,  # noqa: F401 -- re-export
    Product_Line,  # noqa: F401 -- re-export
)
from dojo.product_type.models import Product_Type  # noqa: E402, F401 -- re-export
from dojo.test.models import (  # noqa: E402 -- re-export; class-body FKs below reference these
    IMPORT_ACTIONS,  # noqa: F401 -- re-export
    IMPORT_CLOSED_FINDING,  # noqa: F401 -- re-export
    IMPORT_CREATED_FINDING,  # noqa: F401 -- re-export
    IMPORT_REACTIVATED_FINDING,  # noqa: F401 -- re-export
    IMPORT_UNTOUCHED_FINDING,  # noqa: F401 -- re-export
    Test,
    Test_Import,  # noqa: F401 -- re-export
    Test_Import_Finding_Action,  # noqa: F401 -- re-export
    Test_Type,  # noqa: F401 -- re-export
)


class Report_Type(models.Model):
    name = models.CharField(max_length=255)


class DojoMeta(models.Model):
    name = models.CharField(max_length=120)
    value = models.CharField(max_length=300)
    product = models.ForeignKey("Product",
                                on_delete=models.CASCADE,
                                null=True,
                                editable=False,
                                related_name="product_meta")
    endpoint = models.ForeignKey("Endpoint",
                                 on_delete=models.CASCADE,
                                 null=True,
                                 editable=False,
                                 related_name="endpoint_meta")
    finding = models.ForeignKey("Finding",
                                 on_delete=models.CASCADE,
                                 null=True,
                                 editable=False,
                                 related_name="finding_meta")
    location = models.ForeignKey("Location",
                                 on_delete=models.CASCADE,
                                 null=True,
                                 editable=False,
                                 related_name="location_meta")

    class Meta:
        unique_together = (("product", "name"),
                           ("endpoint", "name"),
                           ("finding", "name"),
                           ("location", "name"))

    def __str__(self):
        return f"{self.name}: {self.value}"

    """
    Verify that this metadata entry belongs only to one object.
    """
    def clean(self):

        ids = [self.product_id,
               self.endpoint_id,
               self.finding_id,
               self.location_id]
        ids_count = 0

        for obj_id in ids:
            if obj_id is not None:
                ids_count += 1

        if ids_count == 0:
            msg = "Metadata entries need either a product, endpoint, location or a finding"
            raise ValidationError(msg)
        if ids_count > 1:
            msg = "Metadata entries may not have more than one relation, either a product, endpoint, location or a finding"
            raise ValidationError(msg)


class SLA_Configuration(models.Model):
    name = models.CharField(max_length=128, unique=True, blank=False, verbose_name=_("Custom SLA Name"),
        help_text=_("A unique name for the set of SLAs."))
    description = models.CharField(
        max_length=512,
        null=True,
        blank=True)
    critical = models.IntegerField(
        default=7,
        verbose_name=_("Critical Finding SLA Days"),
        help_text=_("The number of days to remediate a critical finding."))
    enforce_critical = models.BooleanField(
        default=True,
        verbose_name=_("Enforce Critical Finding SLA Days"),
        help_text=_("When enabled, critical findings will be assigned an SLA expiration date based on the critical finding SLA days within this SLA configuration."))
    high = models.IntegerField(
        default=30,
        verbose_name=_("High Finding SLA Days"),
        help_text=_("The number of days to remediate a high finding."))
    enforce_high = models.BooleanField(
        default=True,
        verbose_name=_("Enforce High Finding SLA Days"),
        help_text=_("When enabled, high findings will be assigned an SLA expiration date based on the high finding SLA days within this SLA configuration."))
    medium = models.IntegerField(
        default=90,
        verbose_name=_("Medium Finding SLA Days"),
        help_text=_("The number of days to remediate a medium finding."))
    enforce_medium = models.BooleanField(
        default=True,
        verbose_name=_("Enforce Medium Finding SLA Days"),
        help_text=_("When enabled, medium findings will be assigned an SLA expiration date based on the medium finding SLA days within this SLA configuration."))
    low = models.IntegerField(
        default=120,
        verbose_name=_("Low Finding SLA Days"),
        help_text=_("The number of days to remediate a low finding."))
    enforce_low = models.BooleanField(
        default=True,
        verbose_name=_("Enforce Low Finding SLA Days"),
        help_text=_("When enabled, low findings will be assigned an SLA expiration date based on the low finding SLA days within this SLA configuration."))
    restart_sla_on_reactivation = models.BooleanField(
        default=False,
        verbose_name=_("Restart SLA when findings are reactivated"),
        help_text=_("When enabled, findings that were previously mitigated but are reactivated durign reimport will have their SLA period restarted."))
    async_updating = models.BooleanField(
        default=False,
        help_text=_("Findings under this SLA configuration are asynchronously being updated"))

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        # get the initial sla config before saving (if this is an existing sla config)
        initial_sla_config = None
        if self.pk is not None:
            initial_sla_config = SLA_Configuration.objects.get(pk=self.pk)
            # if initial config exists and async finding update is already running, revert sla config before saving
            if initial_sla_config and self.async_updating:
                self.critical = initial_sla_config.critical
                self.enforce_critical = initial_sla_config.enforce_critical
                self.high = initial_sla_config.high
                self.enforce_high = initial_sla_config.enforce_high
                self.medium = initial_sla_config.medium
                self.enforce_medium = initial_sla_config.enforce_medium
                self.low = initial_sla_config.low
                self.enforce_low = initial_sla_config.enforce_low

        super().save(*args, **kwargs)

        # if the initial sla config exists and async finding update is not running
        if initial_sla_config is not None and not self.async_updating:
            # check which sla days fields changed based on severity
            severities = []
            if (initial_sla_config.critical != self.critical) or (initial_sla_config.enforce_critical != self.enforce_critical):
                severities.append("Critical")
            if (initial_sla_config.high != self.high) or (initial_sla_config.enforce_high != self.enforce_high):
                severities.append("High")
            if (initial_sla_config.medium != self.medium) or (initial_sla_config.enforce_medium != self.enforce_medium):
                severities.append("Medium")
            if (initial_sla_config.low != self.low) or (initial_sla_config.enforce_low != self.enforce_low):
                severities.append("Low")
            # if severities have changed, update finding sla expiration dates with those severities
            if severities:
                # set the async updating flag to true for this sla config
                self.async_updating = True
                super().save(*args, **kwargs)
                # set the async updating flag to true for all products using this sla config
                products = Product.objects.filter(sla_configuration=self)
                for product in products:
                    product.async_updating = True
                    super(Product, product).save()
                # launch the async task to update all finding sla expiration dates
                from dojo.sla_config.helpers import async_update_sla_expiration_dates_sla_config_sync  # noqa: I001, PLC0415 circular import
                from dojo.celery_dispatch import dojo_dispatch_task  # noqa: PLC0415 circular import

                dojo_dispatch_task(
                    async_update_sla_expiration_dates_sla_config_sync,
                    self.id,
                    list(products.values_list("id", flat=True)),
                    severities=severities,
                )
                # The async task refetches and resets async_updating on its own copy.
                # Mirror that on this in-memory instance so a subsequent save() on the
                # same instance does not trigger the lock-revert path at line 1058.
                self.async_updating = False

    def clean(self):
        sla_days = [self.critical, self.high, self.medium, self.low]

        for sla_day in sla_days:
            if sla_day < 1:
                msg = "SLA Days must be at least 1"
                raise ValidationError(msg)

    def delete(self, *args, **kwargs):
        logger.debug("%d sla configuration delete", self.id)

        if self.id != 1:
            super().delete(*args, **kwargs)
        else:
            msg = "Unable to delete default SLA Configuration"
            raise ValidationError(msg)

    def get_summary(self):
        return f"{self.name} - Critical: {self.critical}, High: {self.high}, Medium: {self.medium}, Low: {self.low}"


class Tool_Type(models.Model):
    name = models.CharField(max_length=200)
    description = models.CharField(max_length=2000, null=True, blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class Tool_Configuration(models.Model):
    name = models.CharField(max_length=200, null=False)
    description = models.CharField(max_length=2000, null=True, blank=True)
    url = models.CharField(max_length=2000, null=True, blank=True)
    tool_type = models.ForeignKey(Tool_Type, related_name="tool_type", on_delete=models.CASCADE)
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
    password = models.CharField(max_length=600, null=True, blank=True)
    auth_title = models.CharField(max_length=200, null=True, blank=True,
                                  verbose_name=_("Title for SSH/API Key"))
    ssh = models.CharField(max_length=6000, null=True, blank=True)
    api_key = models.CharField(max_length=600, null=True, blank=True,
                               verbose_name=_("API Key"))

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


# declare form here as we can't import forms.py due to circular imports not even locally
class ToolConfigForm_Admin(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, required=False)
    api_key = forms.CharField(widget=forms.PasswordInput, required=False)
    ssh = forms.CharField(widget=forms.PasswordInput, required=False)

    # django doesn't seem to have an easy way to handle password fields as PasswordInput requires reentry of passwords
    password_from_db = None
    ssh_from_db = None
    api_key_from_db = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance:
            # keep password from db to use if the user entered no password
            self.password_from_db = self.instance.password
            self.ssh_from_db = self.instance.ssh
            self.api_key = self.instance.api_key

    def clean(self):
        cleaned_data = super().clean()
        if not cleaned_data["password"] and not cleaned_data["ssh"] and not cleaned_data["api_key"]:
            cleaned_data["password"] = self.password_from_db
            cleaned_data["ssh"] = self.ssh_from_db
            cleaned_data["api_key"] = self.api_key_from_db

        return cleaned_data


class Tool_Configuration_Admin(admin.ModelAdmin):
    form = ToolConfigForm_Admin


class Network_Locations(models.Model):
    location = models.CharField(max_length=500, help_text=_("Location of network testing: Examples: VPN, Internet or Internal."))

    def __str__(self):
        return self.location


from dojo.engagement.models import (  # noqa: E402 -- re-export; class-body FKs below reference these
    ENGAGEMENT_STATUS_CHOICES,  # noqa: F401 -- re-export
    Engagement,
    Engagement_Presets,  # noqa: F401 -- re-export
)


class CWE(models.Model):
    url = models.CharField(max_length=1000)
    description = models.CharField(max_length=2000)
    number = models.IntegerField()


class Endpoint_Params(models.Model):
    param = models.CharField(max_length=150)
    value = models.CharField(max_length=150)
    method_type = (("GET", "GET"),
                   ("POST", "POST"))
    method = models.CharField(max_length=20, blank=False, null=True, choices=method_type)


class Endpoint_Status(models.Model):
    date = models.DateField(default=get_current_date)
    last_modified = models.DateTimeField(null=True, editable=False, default=get_current_datetime)
    mitigated = models.BooleanField(default=False, blank=True)
    mitigated_time = models.DateTimeField(editable=False, null=True, blank=True)
    mitigated_by = models.ForeignKey(Dojo_User, editable=True, null=True, on_delete=models.RESTRICT)
    false_positive = models.BooleanField(default=False, blank=True)
    out_of_scope = models.BooleanField(default=False, blank=True)
    risk_accepted = models.BooleanField(default=False, blank=True)
    endpoint = models.ForeignKey("Endpoint", null=False, blank=False, on_delete=models.CASCADE, related_name="status_endpoint")
    finding = models.ForeignKey("Finding", null=False, blank=False, on_delete=models.CASCADE, related_name="status_finding")

    class Meta:
        indexes = [
            models.Index(fields=["finding", "mitigated"]),
            models.Index(fields=["endpoint", "mitigated"]),
            # Optimize frequent lookups of "active" statuses (mitigated/flags all False)
            models.Index(
                name="idx_eps_active_by_endpoint",
                fields=["endpoint"],
                condition=Q(mitigated=False, false_positive=False, out_of_scope=False, risk_accepted=False),
            ),
            models.Index(
                name="idx_eps_active_by_finding",
                fields=["finding"],
                condition=Q(mitigated=False, false_positive=False, out_of_scope=False, risk_accepted=False),
            ),
        ]
        constraints = [
            models.UniqueConstraint(fields=["finding", "endpoint"], name="endpoint-finding relation"),
        ]

    def __str__(self):
        with Endpoint.allow_endpoint_init():  # TODO: Delete this after the move to Locations
            return f"'{self.finding}' on '{self.endpoint}'"

    def copy(self, finding=None):
        copy = copy_model_util(self)
        current_endpoint = self.endpoint
        if finding:
            copy.finding = finding
        copy.endpoint = current_endpoint
        copy.save()

        return copy

    @property
    def age(self):

        diff = self.mitigated_time.date() - self.date if self.mitigated else get_current_date() - self.date
        days = diff.days
        return max(0, days)


class Endpoint(models.Model):
    protocol = models.CharField(null=True, blank=True, max_length=20,
                                 help_text=_("The communication protocol/scheme such as 'http', 'ftp', 'dns', etc."))
    userinfo = models.CharField(null=True, blank=True, max_length=500,
                              help_text=_("User info as 'alice', 'bob', etc."))
    host = models.CharField(null=True, blank=True, max_length=500,
                            help_text=_("The host name or IP address. It must not include the port number. "
                                      "For example '127.0.0.1', 'localhost', 'yourdomain.com'."))
    port = models.IntegerField(null=True, blank=True,
                               help_text=_("The network port associated with the endpoint."))
    path = models.CharField(null=True, blank=True, max_length=500,
                            help_text=_("The location of the resource, it must not start with a '/'. For example "
                                      "endpoint/420/edit"))
    query = models.CharField(null=True, blank=True, max_length=1000,
                             help_text=_("The query string, the question mark should be omitted."
                                       "For example 'group=4&team=8'"))
    fragment = models.CharField(null=True, blank=True, max_length=500,
                                help_text=_("The fragment identifier which follows the hash mark. The hash mark should "
                                          "be omitted. For example 'section-13', 'paragraph-2'."))
    product = models.ForeignKey(Product, null=True, blank=True, on_delete=models.CASCADE)
    endpoint_params = models.ManyToManyField(Endpoint_Params, blank=True, editable=False)
    findings = models.ManyToManyField("Finding",
                                      blank=True,
                                      verbose_name=_("Findings"),
                                      through=Endpoint_Status)

    tags = TagField(blank=True, force_lowercase=True, help_text=_("Add tags that help describe this endpoint. Choose from the list or add new tags. Press Enter key to add."))
    inherited_tags = TagField(blank=True, force_lowercase=True, help_text=_("Internal use tags sepcifically for maintaining parity with product. This field will be present as a subset in the tags field"))

    class Meta:
        ordering = ["product", "host", "protocol", "port", "userinfo", "path", "query", "fragment"]
        indexes = [
            models.Index(fields=["product"]),
            # Fast case-insensitive equality on host within product scope
            models.Index(
                F("product"),
                Lower("host"),
                name="idx_ep_product_lower_host",
            ),
        ]

    def __init__(self, *args, **kwargs):
        if settings.V3_FEATURE_LOCATIONS and not getattr(self, "_allow_v3_init", False):
            msg = "Endpoint model is deprecated when V3_FEATURE_LOCATIONS is enabled"
            raise NotImplementedError(msg)
        super().__init__(*args, **kwargs)

    def __hash__(self):
        return self.__str__().__hash__()

    def __eq__(self, other):
        if isinstance(other, Endpoint):
            contents_match = str(self) == str(other)
            # Use product_id (cached integer) instead of self.product to avoid
            # triggering a FK lookup on every comparison inside NestedObjects.add_edge.
            if self.product_id is not None and other.product_id is not None:
                return self.product_id == other.product_id and contents_match
            return contents_match

        return NotImplemented

    def __str__(self):
        try:
            if self.host:
                dummy_scheme = "dummy-scheme"  # workaround for https://github.com/python-hyper/hyperlink/blob/b8c9152cd826bbe8e6cc125648f3738235019705/src/hyperlink/_url.py#L988
                url = hyperlink.EncodedURL(
                    scheme=self.protocol or dummy_scheme,
                    userinfo=self.userinfo or "",
                    host=self.host,
                    port=self.port,
                    path=tuple(self.path.split("/")) if self.path else (),
                    query=tuple(
                        (
                            qe.split("=", 1)
                            if "=" in qe
                            else (qe, None)
                        )
                        for qe in self.query.split("&")
                    ) if self.query else (),  # inspired by https://github.com/python-hyper/hyperlink/blob/b8c9152cd826bbe8e6cc125648f3738235019705/src/hyperlink/_url.py#L1427
                    fragment=self.fragment or "",
                )
                # Return a normalized version of the URL to avoid differences where there shouldn't be any difference.
                # Example: https://google.com and https://google.com:443
                normalize_path = self.path  # it used to add '/' at the end of host
                clean_url = url.normalize(scheme=True, host=True, path=normalize_path, query=True, fragment=True, userinfo=True, percents=True).to_uri().to_text()
                if not self.protocol:
                    if clean_url[:len(dummy_scheme) + 3] == (dummy_scheme + "://"):
                        clean_url = clean_url[len(dummy_scheme) + 3:]
                    else:
                        msg = "hyperlink lib did not create URL as was expected"
                        raise ValueError(msg)
                return clean_url
            msg = "Missing host"
            raise ValueError(msg)
        except:
            url = ""
            if self.protocol:
                url += f"{self.protocol}://"
            if self.userinfo:
                url += f"{self.userinfo}@"
            if self.host:
                url += self.host
            if self.port:
                url += f":{self.port}"
            if self.path:
                url += "{}{}".format("/" if self.path[0] != "/" else "", self.path)
            if self.query:
                url += f"?{self.query}"
            if self.fragment:
                url += f"#{self.fragment}"
            return url

    def get_absolute_url(self):
        return reverse("view_endpoint", args=[str(self.id)])

    @classmethod
    @contextlib.contextmanager
    def allow_endpoint_init(cls):
        # When migrating to Locations, Endpoints are not deleted (hooray backup!). Disallowing the initialization of
        # Endpoints is a good way to catch where they might still be used (oops!). However, there are some circumstances
        # -- object deletes -- where Django itself attempts to instantiate an Endpoint object. This, we need to allow:
        # if a user wants to delete an object, including whatever Endpoints are attached to it, they should be able to.
        # This context manager allows code to initialize Endpoints at our discretion.
        old = getattr(cls, "_allow_v3_init", None)
        cls._allow_v3_init = True
        try:
            yield
        finally:
            cls._allow_v3_init = old

    def clean(self):
        errors = []
        null_char_list = ["0x00", "\x00"]
        db_type = connection.vendor
        if self.protocol is not None:
            if not re.match(r"^[A-Za-z][A-Za-z0-9\.\-\+]+$", self.protocol):  # https://tools.ietf.org/html/rfc3986#section-3.1
                errors.append(ValidationError(f'Protocol "{self.protocol}" has invalid format'))
            if not self.protocol:
                self.protocol = None

        if self.userinfo is not None:
            if not re.match(r"^[A-Za-z0-9\.\-_~%\!\$&\'\(\)\*\+,;=:]+$", self.userinfo):  # https://tools.ietf.org/html/rfc3986#section-3.2.1
                errors.append(ValidationError(f'Userinfo "{self.userinfo}" has invalid format'))
            if not self.userinfo:
                self.userinfo = None

        if self.host:
            if not re.match(r"^[A-Za-z0-9_\-\+][A-Za-z0-9_\.\-\+]+$", self.host):
                try:
                    validate_ipv46_address(self.host)
                except ValidationError:
                    errors.append(ValidationError(f'Host "{self.host}" has invalid format'))
        else:
            errors.append(ValidationError("Host must not be empty"))

        if self.port is not None:
            try:
                int_port = int(self.port)
                if not (0 <= int_port < 65536):
                    errors.append(ValidationError(f'Port "{self.port}" has invalid format - out of range'))
                self.port = int_port
            except ValueError:
                errors.append(ValidationError(f'Port "{self.port}" has invalid format - it is not a number'))

        if self.path is not None:
            while len(self.path) > 0 and self.path[0] == "/":  # Endpoint store "root-less" path
                self.path = self.path[1:]
            if any(null_char in self.path for null_char in null_char_list):
                old_value = self.path
                if "postgres" in db_type:
                    action_string = "Postgres does not accept NULL character. Attempting to replace with %00..."
                    for remove_str in null_char_list:
                        self.path = self.path.replace(remove_str, "%00")
                    logger.error('Path "%s" has invalid format - It contains the NULL character. The following action was taken: %s', old_value, action_string)
            if not self.path:
                self.path = None

        if self.query is not None:
            if len(self.query) > 0 and self.query[0] == "?":
                self.query = self.query[1:]
            if any(null_char in self.query for null_char in null_char_list):
                old_value = self.query
                if "postgres" in db_type:
                    action_string = "Postgres does not accept NULL character. Attempting to replace with %00..."
                    for remove_str in null_char_list:
                        self.query = self.query.replace(remove_str, "%00")
                    logger.error('Query "%s" has invalid format - It contains the NULL character. The following action was taken: %s', old_value, action_string)
            if not self.query:
                self.query = None

        if self.fragment is not None:
            if len(self.fragment) > 0 and self.fragment[0] == "#":
                self.fragment = self.fragment[1:]
            if any(null_char in self.fragment for null_char in null_char_list):
                old_value = self.fragment
                if "postgres" in db_type:
                    action_string = "Postgres does not accept NULL character. Attempting to replace with %00..."
                    for remove_str in null_char_list:
                        self.fragment = self.fragment.replace(remove_str, "%00")
                    logger.error('Fragment "%s" has invalid format - It contains the NULL character. The following action was taken: %s', old_value, action_string)
            if not self.fragment:
                self.fragment = None

        if errors:
            raise ValidationError(errors)

    @property
    def is_broken(self):
        try:
            self.clean()
        except:
            return True
        else:
            return not self.product

    @property
    def mitigated(self):
        return not self.vulnerable

    @property
    def vulnerable(self):
        return Endpoint_Status.objects.filter(
            endpoint=self,
            mitigated=False,
            false_positive=False,
            out_of_scope=False,
            risk_accepted=False,
        ).count() > 0

    @property
    def findings_count(self):
        return self.findings.all().count()

    def active_findings(self):
        return self.findings.filter(
            active=True,
            out_of_scope=False,
            mitigated__isnull=True,
            false_p=False,
            duplicate=False,
            status_finding__false_positive=False,
            status_finding__out_of_scope=False,
            status_finding__risk_accepted=False,
        ).order_by("numerical_severity")

    def active_verified_findings(self):
        return self.findings.filter(
            active=True,
            verified=True,
            out_of_scope=False,
            mitigated__isnull=True,
            false_p=False,
            duplicate=False,
            status_finding__false_positive=False,
            status_finding__out_of_scope=False,
            status_finding__risk_accepted=False,
        ).order_by("numerical_severity")

    @property
    def active_findings_count(self):
        return self.active_findings().count()

    @property
    def active_verified_findings_count(self):
        return self.active_verified_findings().count()

    def host_endpoints(self):
        return Endpoint.objects.filter(host=self.host,
                                       product=self.product).distinct()

    @property
    def host_endpoints_count(self):
        return self.host_endpoints().count()

    def host_mitigated_endpoints(self):
        meps = Endpoint_Status.objects \
                  .filter(endpoint__in=self.host_endpoints()) \
                  .filter(Q(mitigated=True)
                          | Q(false_positive=True)
                          | Q(out_of_scope=True)
                          | Q(risk_accepted=True)
                          | Q(finding__out_of_scope=True)
                          | Q(finding__mitigated__isnull=False)
                          | Q(finding__false_p=True)
                          | Q(finding__duplicate=True)
                          | Q(finding__active=False))
        return Endpoint.objects.filter(status_endpoint__in=meps).distinct()

    @property
    def host_mitigated_endpoints_count(self):
        return self.host_mitigated_endpoints().count()

    def host_findings(self):
        return Finding.objects.filter(endpoints__in=self.host_endpoints()).distinct()

    @property
    def host_findings_count(self):
        return self.host_findings().count()

    def host_active_findings(self):
        return Finding.objects.filter(
            active=True,
            out_of_scope=False,
            mitigated__isnull=True,
            false_p=False,
            duplicate=False,
            status_finding__false_positive=False,
            status_finding__out_of_scope=False,
            status_finding__risk_accepted=False,
            endpoints__in=self.host_endpoints(),
        ).order_by("numerical_severity")

    def host_active_verified_findings(self):
        return Finding.objects.filter(
            active=True,
            verified=True,
            out_of_scope=False,
            mitigated__isnull=True,
            false_p=False,
            duplicate=False,
            status_finding__false_positive=False,
            status_finding__out_of_scope=False,
            status_finding__risk_accepted=False,
            endpoints__in=self.host_endpoints(),
        ).order_by("numerical_severity")

    @property
    def host_active_findings_count(self):
        return self.host_active_findings().count()

    @property
    def host_active_verified_findings_count(self):
        return self.host_active_verified_findings().count()

    def get_breadcrumbs(self):
        bc = self.product.get_breadcrumbs()
        bc += [{"title": self.host,
                "url": reverse("view_endpoint", args=(self.id,))}]
        return bc

    @staticmethod
    def from_uri(uri):
        try:
            url = hyperlink.parse(url=uri)
        except UnicodeDecodeError:
            url = hyperlink.parse(url="//" + urlparse(uri).netloc)
        except hyperlink.URLParseError as e:
            msg = f"Invalid URL format: {e}"
            raise ValidationError(msg)

        query_parts = []  # inspired by https://github.com/python-hyper/hyperlink/blob/b8c9152cd826bbe8e6cc125648f3738235019705/src/hyperlink/_url.py#L1768
        for k, v in url.query:
            if v is None:
                query_parts.append(k)
            else:
                query_parts.append(f"{k}={v}")
        query_string = "&".join(query_parts)

        protocol = url.scheme or None
        userinfo = ":".join(url.userinfo) if url.userinfo not in {(), ("",)} else None
        host = url.host or None
        port = url.port
        path = "/".join(url.path)[:500] if url.path not in {None, (), ("",)} else None
        query = query_string[:1000] if query_string is not None and query_string else None
        fragment = url.fragment[:500] if url.fragment is not None and url.fragment else None

        return Endpoint(
            protocol=protocol,
            userinfo=userinfo,
            host=host,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
        )


class Development_Environment(models.Model):
    name = models.CharField(max_length=200)

    def __str__(self):
        return self.name

    def get_breadcrumbs(self):
        return [{"title": str(self),
                 "url": reverse("edit_dev_env", args=(self.id,))}]


class Sonarqube_Issue(models.Model):
    key = models.CharField(max_length=60, unique=True, help_text=_("SonarQube issue key"))
    status = models.CharField(max_length=20, help_text=_("SonarQube issue status"))
    type = models.CharField(max_length=20, help_text=_("SonarQube issue type"))

    def __str__(self):
        return self.key


class Sonarqube_Issue_Transition(models.Model):
    sonarqube_issue = models.ForeignKey(Sonarqube_Issue, on_delete=models.CASCADE, db_index=True)
    created = models.DateTimeField(auto_now_add=True, null=False)
    finding_status = models.CharField(max_length=100)
    sonarqube_status = models.CharField(max_length=50)
    transitions = models.CharField(max_length=100)

    class Meta:
        ordering = ("-created", )


from dojo.finding.models import (  # noqa: E402 -- re-export; class-body FKs below reference these
    Finding,
    Finding_Group,  # noqa: F401 -- re-export
    Finding_Template,
    Vulnerability_Id,  # noqa: F401 -- re-export
)


class Check_List(models.Model):
    session_management = models.CharField(max_length=50, default="none")
    session_issues = models.ManyToManyField(Finding,
                                            related_name="session_issues",
                                            blank=True)
    encryption_crypto = models.CharField(max_length=50, default="none")
    crypto_issues = models.ManyToManyField(Finding,
                                           related_name="crypto_issues",
                                           blank=True)
    configuration_management = models.CharField(max_length=50, default="")
    config_issues = models.ManyToManyField(Finding,
                                           related_name="config_issues",
                                           blank=True)
    authentication = models.CharField(max_length=50, default="none")
    auth_issues = models.ManyToManyField(Finding,
                                         related_name="auth_issues",
                                         blank=True)
    authorization_and_access_control = models.CharField(max_length=50,
                                                        default="none")
    author_issues = models.ManyToManyField(Finding,
                                           related_name="author_issues",
                                           blank=True)
    data_input_sanitization_validation = models.CharField(max_length=50,
                                                          default="none")
    data_issues = models.ManyToManyField(Finding, related_name="data_issues",
                                         blank=True)
    sensitive_data = models.CharField(max_length=50, default="none")
    sensitive_issues = models.ManyToManyField(Finding,
                                              related_name="sensitive_issues",
                                              blank=True)
    other = models.CharField(max_length=50, default="none")
    other_issues = models.ManyToManyField(Finding, related_name="other_issues",
                                          blank=True)
    engagement = models.ForeignKey(Engagement, editable=False,
                                   related_name="eng_for_check", on_delete=models.CASCADE)

    @staticmethod
    def get_status(pass_fail):
        if pass_fail == "Pass":  # noqa: S105
            return "success"
        if pass_fail == "Fail":  # noqa: S105
            return "danger"
        return "warning"

    def get_breadcrumb(self):
        bc = self.engagement.get_breadcrumb()
        bc += [{"title": "Check List",
                "url": reverse("complete_checklist",
                               args=(self.engagement.id,))}]
        return bc


class BurpRawRequestResponse(models.Model):
    finding = models.ForeignKey(Finding, blank=True, null=True, on_delete=models.CASCADE)
    burpRequestBase64 = models.BinaryField()
    burpResponseBase64 = models.BinaryField()

    def get_request(self):
        return str(base64.b64decode(self.burpRequestBase64), errors="ignore")

    def get_response(self):
        res = str(base64.b64decode(self.burpResponseBase64), errors="ignore")
        # Removes all blank lines
        return re.sub(r"\n\s*\n", "\n", res)


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

    accepted_findings = models.ManyToManyField(Finding)

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
    owner = models.ForeignKey(Dojo_User, editable=True, on_delete=models.RESTRICT, help_text=_("User in DefectDojo owning this acceptance. Only the owner and staff users can edit the risk acceptance."))

    expiration_date = models.DateTimeField(default=None, null=True, blank=True, help_text=_("When the risk acceptance expires, the findings will be reactivated (unless disabled below)."))
    expiration_date_warned = models.DateTimeField(default=None, null=True, blank=True, help_text=_("(readonly) Date at which notice about the risk acceptance expiration was sent."))
    expiration_date_handled = models.DateTimeField(default=None, null=True, blank=True, help_text=_("(readonly) When the risk acceptance expiration was handled (manually or by the daily job)."))
    reactivate_expired = models.BooleanField(null=False, blank=False, default=True, verbose_name=_("Reactivate findings on expiration"), help_text=_("Reactivate findings when risk acceptance expires?"))
    restart_sla_expired = models.BooleanField(default=False, null=False, verbose_name=_("Restart SLA on expiration"), help_text=_("When enabled, the SLA for findings is restarted when the risk acceptance expires."))

    notes = models.ManyToManyField(Notes, editable=False)
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


class FileAccessToken(models.Model):

    """
    This will allow reports to request the images without exposing the
    media root to the world without
    authentication
    """

    user = models.ForeignKey(Dojo_User, null=False, blank=False, on_delete=models.CASCADE)
    file = models.ForeignKey(FileUpload, null=False, blank=False, on_delete=models.CASCADE)
    token = models.CharField(max_length=255)
    size = models.CharField(max_length=9,
                            choices=(
                                ("small", "Small"),
                                ("medium", "Medium"),
                                ("large", "Large"),
                                ("thumbnail", "Thumbnail"),
                                ("original", "Original")),
                            default="medium")

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = uuid4()
        return super().save(*args, **kwargs)


ANNOUNCEMENT_STYLE_CHOICES = (
    ("info", "Info"),
    ("success", "Success"),
    ("warning", "Warning"),
    ("danger", "Danger"),
)


class Announcement(models.Model):
    message = models.CharField(max_length=500,
                                help_text=_("This dismissable message will be displayed on all pages for authenticated users. It can contain basic html tags, for example <a href='https://www.fred.com' style='color: #337ab7;' target='_blank'>https://example.com</a>"),
                                default="")
    style = models.CharField(max_length=64, choices=ANNOUNCEMENT_STYLE_CHOICES, default="info",
                            help_text=_("The style of banner to display. (info, success, warning, danger)"))
    dismissable = models.BooleanField(default=False,
                                      null=False,
                                      blank=True,
                                      verbose_name=_("Dismissable?"),
                                      help_text=_("Ticking this box allows users to dismiss the current announcement"),
                                      )


class UserAnnouncement(models.Model):
    announcement = models.ForeignKey(Announcement, null=True, editable=False, on_delete=models.CASCADE, related_name="user_announcement")
    user = models.ForeignKey(Dojo_User, null=True, editable=False, on_delete=models.CASCADE)


class BannerConf(models.Model):
    banner_enable = models.BooleanField(default=False, null=True, blank=True)
    banner_message = models.CharField(max_length=500, help_text=_("This message will be displayed on the login page. It can contain basic html tags, for example <a href='https://www.fred.com' style='color: #337ab7;' target='_blank'>https://example.com</a>"), default="")


from dojo.github.models import (  # noqa: E402, F401 -- backward compat
    GITHUB_Clone,
    GITHUB_Conf,
    GITHUB_Details_Cache,
    GITHUB_Issue,
    GITHUB_PKey,
)
from dojo.jira.models import (  # noqa: E402,F401 backward compat
    JIRA_Instance,
    JIRA_Instance_Admin,
    JIRA_Issue,
    JIRA_Project,
)
from dojo.notifications.admin import NotificationsAdmin  # noqa: E402, F401  -- backward compat
from dojo.notifications.models import (  # noqa: E402, F401  -- backward compat
    DEFAULT_NOTIFICATION,
    NOTIFICATION_CHOICE_ALERT,
    NOTIFICATION_CHOICE_MAIL,
    NOTIFICATION_CHOICE_MSTEAMS,
    NOTIFICATION_CHOICE_SLACK,
    NOTIFICATION_CHOICE_WEBHOOKS,
    NOTIFICATION_CHOICES,
    Alerts,
    Notification_Webhooks,
    Notifications,
)


class Tool_Product_Settings(models.Model):
    name = models.CharField(max_length=200, null=False)
    description = models.CharField(max_length=2000, null=True, blank=True)
    url = models.CharField(max_length=2000, null=True, blank=True)
    product = models.ForeignKey(Product, default=1, editable=False, on_delete=models.CASCADE)
    tool_configuration = models.ForeignKey(Tool_Configuration, null=False,
                                           related_name="tool_configuration", on_delete=models.CASCADE)
    tool_project_id = models.CharField(max_length=200, null=True, blank=True)
    notes = models.ManyToManyField(Notes, blank=True, editable=False)

    class Meta:
        ordering = ["name"]


class Tool_Product_History(models.Model):
    product = models.ForeignKey(Tool_Product_Settings, editable=False, on_delete=models.CASCADE)
    last_scan = models.DateTimeField(null=False, editable=False, default=now)
    succesfull = models.BooleanField(default=True, verbose_name=_("Succesfully"))
    configuration_details = models.CharField(max_length=2000, null=True,
                                             blank=True)


class Language_Type(models.Model):
    language = models.CharField(max_length=100, null=False, unique=True)
    color = models.CharField(max_length=7, null=True, blank=True, verbose_name=_("HTML color"))

    def __str__(self):
        return self.language


class Languages(models.Model):
    language = models.ForeignKey(Language_Type, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    user = models.ForeignKey(Dojo_User, editable=True, blank=True, null=True, on_delete=models.RESTRICT)
    files = models.IntegerField(blank=True, null=True, verbose_name=_("Number of files"))
    blank = models.IntegerField(blank=True, null=True, verbose_name=_("Number of blank lines"))
    comment = models.IntegerField(blank=True, null=True, verbose_name=_("Number of comment lines"))
    code = models.IntegerField(blank=True, null=True, verbose_name=_("Number of code lines"))
    created = models.DateTimeField(auto_now_add=True, null=False)

    class Meta:
        unique_together = [("language", "product")]

    def __str__(self):
        return self.language.language


class App_Analysis(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    name = models.CharField(max_length=200, null=False)
    user = models.ForeignKey(Dojo_User, editable=True, on_delete=models.RESTRICT)
    confidence = models.IntegerField(blank=True, null=True, verbose_name=_("Confidence level"))
    version = models.CharField(max_length=200, null=True, blank=True, verbose_name=_("Version Number"))
    icon = models.CharField(max_length=200, null=True, blank=True)
    website = models.URLField(max_length=400, null=True, blank=True)
    website_found = models.URLField(max_length=400, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True, null=False)

    tags = TagField(blank=True, force_lowercase=True)

    def __str__(self):
        return self.name + " | " + self.product.name


class Objects_Review(models.Model):
    name = models.CharField(max_length=100, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True, null=False)

    def __str__(self):
        return self.name


class Objects_Product(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    name = models.CharField(max_length=100, null=True, blank=True)
    path = models.CharField(max_length=600, verbose_name=_("Full file path"),
                            null=True, blank=True)
    folder = models.CharField(max_length=400, verbose_name=_("Folder"),
                              null=True, blank=True)
    artifact = models.CharField(max_length=400, verbose_name=_("Artifact"),
                                null=True, blank=True)
    review_status = models.ForeignKey(Objects_Review, on_delete=models.CASCADE)
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


class Testing_Guide_Category(models.Model):
    name = models.CharField(max_length=300)
    created = models.DateTimeField(auto_now_add=True, null=False)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name


class Testing_Guide(models.Model):
    testing_guide_category = models.ForeignKey(Testing_Guide_Category, on_delete=models.CASCADE)
    identifier = models.CharField(max_length=20, blank=True, null=True, help_text=_("Test Unique Identifier"))
    name = models.CharField(max_length=400, help_text=_("Name of the test"))
    summary = models.CharField(max_length=800, help_text=_("Summary of the test"))
    objective = models.CharField(max_length=800, help_text=_("Objective of the test"))
    how_to_test = models.TextField(default=None, help_text=_("How to test the objective"))
    results_expected = models.CharField(max_length=800, help_text=_("What the results look like for a test"))
    created = models.DateTimeField(auto_now_add=True, null=False)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.testing_guide_category.name + ": " + self.name


class Benchmark_Type(models.Model):
    name = models.CharField(max_length=300)
    version = models.CharField(max_length=15)
    source = (("PCI", "PCI"),
              ("OWASP ASVS", "OWASP ASVS"),
              ("OWASP Mobile ASVS", "OWASP Mobile ASVS"))
    benchmark_source = models.CharField(max_length=20, blank=False,
                                        null=True, choices=source,
                                        default="OWASP ASVS")
    created = models.DateTimeField(auto_now_add=True, null=False)
    updated = models.DateTimeField(auto_now=True)
    enabled = models.BooleanField(default=True)

    def __str__(self):
        return self.name + " " + self.version


class Benchmark_Category(models.Model):
    type = models.ForeignKey(Benchmark_Type, verbose_name=_("Benchmark Type"), on_delete=models.CASCADE)
    name = models.CharField(max_length=300)
    objective = models.TextField()
    references = models.TextField(blank=True, null=True)
    enabled = models.BooleanField(default=True)
    created = models.DateTimeField(auto_now_add=True, null=False)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name + ": " + self.type.name


class Benchmark_Requirement(models.Model):
    category = models.ForeignKey(Benchmark_Category, on_delete=models.CASCADE)
    objective_number = models.CharField(max_length=15, null=True, blank=True)
    objective = models.TextField()
    references = models.TextField(blank=True, null=True)
    level_1 = models.BooleanField(default=False)
    level_2 = models.BooleanField(default=False)
    level_3 = models.BooleanField(default=False)
    enabled = models.BooleanField(default=True)
    cwe_mapping = models.ManyToManyField(CWE, blank=True)
    testing_guide = models.ManyToManyField(Testing_Guide, blank=True)
    created = models.DateTimeField(auto_now_add=True, null=False)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.objective_number) + ": " + self.category.name


class Benchmark_Product(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    control = models.ForeignKey(Benchmark_Requirement, on_delete=models.CASCADE)
    pass_fail = models.BooleanField(default=False, verbose_name=_("Pass"),
                                    help_text=_("Does the product meet the requirement?"))
    enabled = models.BooleanField(default=True,
                                  help_text=_("Applicable for this specific product."))
    notes = models.ManyToManyField(Notes, blank=True, editable=False)
    created = models.DateTimeField(auto_now_add=True, null=False)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("product", "control")]

    def __str__(self):
        return self.product.name + ": " + self.control.objective_number + ": " + self.control.category.name


class Benchmark_Product_Summary(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    benchmark_type = models.ForeignKey(Benchmark_Type, on_delete=models.CASCADE)
    asvs_level = (("Level 1", "Level 1"),
                    ("Level 2", "Level 2"),
                    ("Level 3", "Level 3"))
    desired_level = models.CharField(max_length=15,
                                     null=False, choices=asvs_level,
                                     default="Level 1")
    current_level = models.CharField(max_length=15, blank=True,
                                     null=True, choices=asvs_level,
                                     default="None")
    asvs_level_1_benchmark = models.IntegerField(null=False, default=0, help_text=_("Total number of active benchmarks for this application."))
    asvs_level_1_score = models.IntegerField(null=False, default=0, help_text=_("ASVS Level 1 Score"))
    asvs_level_2_benchmark = models.IntegerField(null=False, default=0, help_text=_("Total number of active benchmarks for this application."))
    asvs_level_2_score = models.IntegerField(null=False, default=0, help_text=_("ASVS Level 2 Score"))
    asvs_level_3_benchmark = models.IntegerField(null=False, default=0, help_text=_("Total number of active benchmarks for this application."))
    asvs_level_3_score = models.IntegerField(null=False, default=0, help_text=_("ASVS Level 3 Score"))
    publish = models.BooleanField(default=False, help_text=_("Publish score to Product."))
    created = models.DateTimeField(auto_now_add=True, null=False)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("product", "benchmark_type")]

    def __str__(self):
        return self.product.name + ": " + self.benchmark_type.name


# ==========================
# Defect Dojo Engaegment Surveys
# ==============================
with warnings.catch_warnings(action="ignore", category=ManagerInheritanceWarning):
    class Question(PolymorphicModel, TimeStampedModel):

        """Represents a question."""

        class Meta:
            ordering = ["order"]

        order = models.PositiveIntegerField(default=1,
                                            help_text=_("The render order"))

        optional = models.BooleanField(
            default=False,
            help_text=_("If selected, user doesn't have to answer this question"))

        text = models.TextField(blank=False, help_text=_("The question text"), default="")
        objects = models.Manager()
        polymorphic = PolymorphicManager()

        def __str__(self):
            return self.text


class TextQuestion(Question):

    """Question with a text answer"""

    objects = PolymorphicManager()

    def get_form(self):
        """Returns the form for this model"""
        from .forms import TextQuestionForm  # noqa: PLC0415
        return TextQuestionForm


class Choice(TimeStampedModel):

    """Model to store the choices for multi choice questions"""

    order = models.PositiveIntegerField(default=1)

    label = models.TextField(default="")

    class Meta:
        ordering = ["order"]

    def __str__(self):
        return self.label


class ChoiceQuestion(Question):

    """
    Question with answers that are chosen from a list of choices defined
    by the user.
    """

    multichoice = models.BooleanField(default=False,
                                      help_text=_("Select one or more"))
    choices = models.ManyToManyField(Choice)
    objects = PolymorphicManager()

    def get_form(self):
        """Returns the form for this model"""
        from .forms import ChoiceQuestionForm  # noqa: PLC0415
        return ChoiceQuestionForm


# meant to be a abstract survey, identified by name for purpose
class Engagement_Survey(models.Model):
    name = models.CharField(max_length=200, null=False, blank=False,
                            editable=True, default="")
    description = models.TextField(editable=True, default="")
    questions = models.ManyToManyField(Question)
    active = models.BooleanField(default=True)

    class Meta:
        verbose_name = _("Engagement Survey")
        verbose_name_plural = "Engagement Surveys"
        ordering = ("-active", "name")

    def __str__(self):
        return self.name


# meant to be an answered survey tied to an engagement

class Answered_Survey(models.Model):
    # tie this to a specific engagement
    engagement = models.ForeignKey(Engagement, related_name="engagement+",
                                   null=True, blank=False, editable=True,
                                   on_delete=models.CASCADE)
    # what surveys have been answered
    survey = models.ForeignKey(Engagement_Survey, on_delete=models.CASCADE)
    assignee = models.ForeignKey(Dojo_User, related_name="assignee",
                                  null=True, blank=True, editable=True,
                                  default=None, on_delete=models.RESTRICT)
    # who answered it
    responder = models.ForeignKey(Dojo_User, related_name="responder",
                                  null=True, blank=True, editable=True,
                                  default=None, on_delete=models.RESTRICT)
    completed = models.BooleanField(default=False)
    answered_on = models.DateField(null=True)

    class Meta:
        verbose_name = _("Answered Engagement Survey")
        verbose_name_plural = _("Answered Engagement Surveys")

    def __str__(self):
        return self.survey.name


def default_expiration():
    return timezone.now() + timedelta(days=7)


class General_Survey(models.Model):
    survey = models.ForeignKey(Engagement_Survey, on_delete=models.CASCADE)
    num_responses = models.IntegerField(default=0)
    generated = models.DateTimeField(auto_now_add=True, null=True)
    expiration = models.DateTimeField(default=default_expiration)

    class Meta:
        verbose_name = _("General Engagement Survey")
        verbose_name_plural = _("General Engagement Surveys")

    def __str__(self):
        return self.survey.name

    def clean(self):
        if self.expiration and timezone.is_naive(self.expiration):
            self.expiration = timezone.make_aware(self.expiration)


with warnings.catch_warnings(action="ignore", category=ManagerInheritanceWarning):
    class Answer(PolymorphicModel, TimeStampedModel):

        """Base Answer model"""

        question = models.ForeignKey(Question, on_delete=models.CASCADE)

        answered_survey = models.ForeignKey(Answered_Survey,
                                            null=False,
                                            blank=False,
                                            on_delete=models.CASCADE)
        objects = models.Manager()
        polymorphic = PolymorphicManager()


class TextAnswer(Answer):
    answer = models.TextField(
        blank=False,
        help_text=_("The answer text"),
        default="")
    objects = PolymorphicManager()

    def __str__(self):
        return self.answer


class ChoiceAnswer(Answer):
    answer = models.ManyToManyField(
        Choice,
        help_text=_("The selected choices as the answer"))
    objects = PolymorphicManager()

    def __str__(self):
        if len(self.answer.all()):
            return str(self.answer.all()[0])
        return "No Response"


# Audit logging registration is now handled in auditlog.py and configured in apps.py
# This allows for conditional registration of either django-auditlog or django-pghistory
# The audit system is configured in DojoAppConfig.ready() to ensure all models are loaded


from dojo.utils import (  # noqa: E402
    parse_cvss_data,  # noqa: F401 -- backward compat re-export; side-effect loads dojo.utils → dojo.location models
)

tagulous.admin.register(Product.tags)
tagulous.admin.register(Test.tags)
tagulous.admin.register(Test.inherited_tags)
tagulous.admin.register(Finding.tags)
tagulous.admin.register(Finding.inherited_tags)
tagulous.admin.register(Engagement.tags)
tagulous.admin.register(Engagement.inherited_tags)
tagulous.admin.register(Endpoint.tags)
tagulous.admin.register(Endpoint.inherited_tags)
tagulous.admin.register(Finding_Template.tags)
tagulous.admin.register(App_Analysis.tags)
tagulous.admin.register(Objects_Product.tags)

# Benchmarks
admin.site.register(Benchmark_Type)
admin.site.register(Benchmark_Requirement)
admin.site.register(Benchmark_Category)
admin.site.register(Benchmark_Product)
admin.site.register(Benchmark_Product_Summary)

# Testing
admin.site.register(Testing_Guide_Category)
admin.site.register(Testing_Guide)

admin.site.register(Network_Locations)
admin.site.register(Objects_Product)
admin.site.register(Objects_Review)
admin.site.register(Languages)
admin.site.register(Language_Type)
admin.site.register(App_Analysis)
admin.site.register(FileUpload)
admin.site.register(FileAccessToken)
admin.site.register(Risk_Acceptance)
admin.site.register(Check_List)
admin.site.register(Endpoint_Params)
admin.site.register(Endpoint_Status)
admin.site.register(Endpoint)
admin.site.register(UserContactInfo)
admin.site.register(Notes)
admin.site.register(Note_Type)
admin.site.register(Tool_Configuration, Tool_Configuration_Admin)
admin.site.register(Tool_Product_Settings)
admin.site.register(Tool_Type)
admin.site.register(System_Settings)
admin.site.register(SLA_Configuration)
admin.site.register(CWE)
admin.site.register(Regulation)
from dojo.authorization.models import (  # noqa: E402
    Dojo_Group,
    Dojo_Group_Member,
    Global_Role,
    Product_Group,
    Product_Member,
    Product_Type_Group,
    Product_Type_Member,
    Role,
)

admin.site.register(Global_Role)
admin.site.register(Role)
admin.site.register(Dojo_Group)

# SonarQube Integration
admin.site.register(Sonarqube_Issue)
admin.site.register(Sonarqube_Issue_Transition)

admin.site.register(Dojo_Group_Member)
admin.site.register(Product_Member)
admin.site.register(Product_Group)
admin.site.register(Product_Type_Member)
admin.site.register(Product_Type_Group)

admin.site.register(Contact)
admin.site.register(NoteHistory)
admin.site.register(Report_Type)
admin.site.register(DojoMeta)
admin.site.register(Development_Environment)
admin.site.register(BurpRawRequestResponse)
admin.site.register(Announcement)
admin.site.register(UserAnnouncement)
admin.site.register(BannerConf)
admin.site.register(Tool_Product_History)
admin.site.register(General_Survey)
