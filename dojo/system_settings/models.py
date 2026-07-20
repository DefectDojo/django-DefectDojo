from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils.translation import gettext as _


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

    def save(self, *args, **kwargs):
        # Guard against persisting an instance handed back by the read-through
        # cache. ``System_Settings.objects.get()`` returns a snapshot rebuilt from
        # the cached dict (see dojo.middleware.get_cached_system_settings); saving
        # it could overwrite concurrent changes with stale values. Writers must
        # fetch a fresh instance with ``System_Settings.objects.get(no_cache=True)``.
        from dojo.caching import READ_ONLY_CACHE_MARKER, ReadOnlyCachedInstanceError  # noqa: PLC0415 circular import
        if getattr(self, READ_ONLY_CACHE_MARKER, False):
            msg = (
                "Refusing to save a System_Settings instance obtained from the read-through cache "
                "(System_Settings.objects.get()); it is a read-only snapshot. Fetch a fresh instance "
                "with System_Settings.objects.get(no_cache=True) before saving."
            )
            raise ReadOnlyCachedInstanceError(msg)
        super().save(*args, **kwargs)

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
