from pytz import all_timezones

from django import forms
from django.contrib import admin
from django.db import models
from django.utils.translation import gettext as _


class System_Settings(models.Model):
    enable_auditlog = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_('Enable audit logging'),
        help_text=_("With this setting turned on, Dojo maintains an audit log "
                  "of changes made to entities (Findings, Tests, Engagements, Procuts, ...)"
                  "If you run big import you may want to disable this "
                  "because the way django-auditlog currently works, there's a "
                  "big performance hit. Especially during (re-)imports."))
    enable_deduplication = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_('Deduplicate findings'),
        help_text=_("With this setting turned on, Dojo deduplicates findings by "
                  "comparing endpoints, cwe fields, and titles. "
                  "If two findings share a URL and have the same CWE or "
                  "title, Dojo marks the less recent finding as a duplicate. "
                  "When deduplication is enabled, a list of "
                  "deduplicated findings is added to the engagement view."))
    delete_duplicates = models.BooleanField(default=False, blank=False, help_text=_("Requires next setting: maximum number of duplicates to retain."))
    max_dupes = models.IntegerField(blank=True, null=True, default=10,
                                    verbose_name=_('Max Duplicates'),
                                    help_text=_("When enabled, if a single "
                                              "issue reaches the maximum "
                                              "number of duplicates, the "
                                              "oldest will be deleted. Duplicate will not be deleted when left empty. A value of 0 will remove all duplicates."))

    email_from = models.CharField(max_length=200, default='no-reply@example.com', blank=True)

    enable_jira = models.BooleanField(default=False,
                                      verbose_name=_('Enable JIRA integration'),
                                      blank=False)

    enable_jira_web_hook = models.BooleanField(default=False,
                                      verbose_name=_('Enable JIRA web hook'),
                                      help_text=_('Please note: It is strongly recommended to use a secret below and / or IP whitelist the JIRA server using a proxy such as Nginx.'),
                                      blank=False)

    disable_jira_webhook_secret = models.BooleanField(default=False,
                                      verbose_name=_('Disable web hook secret'),
                                      help_text=_('Allows incoming requests without a secret (discouraged legacy behaviour)'),
                                      blank=False)

    # will be set to random / uuid by initializer so null needs to be True
    jira_webhook_secret = models.CharField(max_length=64, blank=False, null=True, verbose_name=_('JIRA Webhook URL'),
                                           help_text=_('Secret needed in URL for incoming JIRA Webhook'))

    jira_choices = (('Critical', 'Critical'),
                    ('High', 'High'),
                    ('Medium', 'Medium'),
                    ('Low', 'Low'),
                    ('Info', 'Info'))
    jira_minimum_severity = models.CharField(max_length=20, blank=True,
                                             null=True, choices=jira_choices,
                                             default='Low')
    jira_labels = models.CharField(max_length=200, blank=True, null=True,
                                   help_text=_('JIRA issue labels space seperated'))

    add_vulnerability_id_to_jira_label = models.BooleanField(default=False,
                                        verbose_name=_('Add vulnerability Id as a JIRA label'),
                                        blank=False)

    enable_github = models.BooleanField(default=False,
                                      verbose_name=_('Enable GITHUB integration'),
                                      blank=False)

    enable_slack_notifications = \
        models.BooleanField(default=False,
                            verbose_name=_('Enable Slack notifications'),
                            blank=False)
    slack_channel = models.CharField(max_length=100, default='', blank=True,
                    help_text=_('Optional. Needed if you want to send global notifications.'))
    slack_token = models.CharField(max_length=100, default='', blank=True,
                                   help_text=_('Token required for interacting '
                                             'with Slack. Get one at '
                                             'https://api.slack.com/tokens'))
    slack_username = models.CharField(max_length=100, default='', blank=True,
                     help_text=_('Optional. Will take your bot name otherwise.'))
    enable_msteams_notifications = \
        models.BooleanField(default=False,
                            verbose_name=_('Enable Microsoft Teams notifications'),
                            blank=False)
    msteams_url = models.CharField(max_length=400, default='', blank=True,
                                    help_text=_('The full URL of the '
                                              'incoming webhook'))
    enable_mail_notifications = models.BooleanField(default=False, blank=False)
    mail_notifications_to = models.CharField(max_length=200, default='',
                                             blank=True)
    false_positive_history = models.BooleanField(default=False, help_text=_("DefectDojo will automatically mark the finding as a false positive if the finding has been previously marked as a false positive. Not needed when using deduplication, advised to not combine these two."))

    url_prefix = models.CharField(max_length=300, default='', blank=True, help_text=_("URL prefix if DefectDojo is installed in it's own virtual subdirectory."))
    team_name = models.CharField(max_length=100, default='', blank=True)
    time_zone = models.CharField(max_length=50,
                                 choices=[(tz, tz) for tz in all_timezones],
                                 default='UTC', blank=False)
    enable_product_grade = models.BooleanField(default=False, verbose_name=_('Enable Product Grading'), help_text=_("Displays a grade letter next to a product to show the overall health."))
    product_grade = models.CharField(max_length=800, blank=True)
    product_grade_a = models.IntegerField(default=90,
                                          verbose_name=_('Grade A'),
                                          help_text=_("Percentage score for an "
                                                    "'A' >="))
    product_grade_b = models.IntegerField(default=80,
                                          verbose_name=_('Grade B'),
                                          help_text=_("Percentage score for a "
                                                    "'B' >="))
    product_grade_c = models.IntegerField(default=70,
                                          verbose_name=_('Grade C'),
                                          help_text=_("Percentage score for a "
                                                    "'C' >="))
    product_grade_d = models.IntegerField(default=60,
                                          verbose_name=_('Grade D'),
                                          help_text=_("Percentage score for a "
                                                    "'D' >="))
    product_grade_f = models.IntegerField(default=59,
                                          verbose_name=_('Grade F'),
                                          help_text=_("Percentage score for an "
                                                    "'F' <="))
    enable_benchmark = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_('Enable Benchmarks'),
        help_text=_("Enables Benchmarks such as the OWASP ASVS "
                  "(Application Security Verification Standard)"))

    enable_template_match = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_('Enable Remediation Advice'),
        help_text=_("Enables global remediation advice and matching on CWE and Title. The text will be replaced for mitigation, impact and references on a finding. Useful for providing consistent impact and remediation advice regardless of the scanner."))

    engagement_auto_close = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Enable Engagement Auto-Close"),
        help_text=_('Closes an engagement after 3 days (default) past due date including last update.'))

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
        verbose_name=_("Enable Notifiy SLA's Breach for active Findings"),
        help_text=_("Enables Notify when time to remediate according to Finding SLA's is breached for active Findings."))

    enable_notify_sla_active_verified = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Enable Notifiy SLA's Breach for active, verified Findings"),
        help_text=_("Enables Notify when time to remediate according to Finding SLA's is breached for active, verified Findings."))

    enable_notify_sla_jira_only = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Enable Notifiy SLA's Breach for Findings linked to JIRA"),
        help_text=_("Enables Notify when time to remediate according to Finding SLA's is breached for Findings that are linked to JIRA issues."))

    allow_anonymous_survey_repsonse = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_('Allow Anonymous Survey Responses'),
        help_text=_("Enable anyone with a link to the survey to answer a survey")
    )
    credentials = models.TextField(max_length=3000, blank=True)
    disclaimer = models.TextField(max_length=3000, default='', blank=True,
                                  verbose_name=_('Custom Disclaimer'),
                                  help_text=_("Include this custom disclaimer on all notifications and generated reports"))
    column_widths = models.TextField(max_length=1500, blank=True)
    drive_folder_ID = models.CharField(max_length=100, blank=True)
    email_address = models.EmailField(max_length=100, blank=True)
    risk_acceptance_form_default_days = models.IntegerField(null=True, blank=True, default=180, help_text=_("Default expiry period for risk acceptance form."))
    risk_acceptance_notify_before_expiration = models.IntegerField(null=True, blank=True, default=10,
                    verbose_name=_('Risk acceptance expiration heads up days'), help_text=_("Notify X days before risk acceptance expires. Leave empty to disable."))
    enable_credentials = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_('Enable credentials'),
        help_text=_("With this setting turned off, credentials will be disabled in the user interface."))
    enable_questionnaires = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_('Enable questionnaires'),
        help_text=_("With this setting turned off, questionnaires will be disabled in the user interface."))
    enable_checklists = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_('Enable checklists'),
        help_text=_("With this setting turned off, checklists will be disabled in the user interface."))
    enable_endpoint_metadata_import = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_('Enable Endpoint Metadata Import'),
        help_text=_("With this setting turned off, endpoint metadata import will be disabled in the user interface."))
    enable_google_sheets = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_('Enable Google Sheets Integration'),
        help_text=_("With this setting turned off, the Google sheets integration will be disabled in the user interface."))
    enable_rules_framework = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_('Enable Rules Framework'),
        help_text=_("With this setting turned off, the rules framwork will be disabled in the user interface."))
    enable_user_profile_editable = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_('Enable user profile for writing'),
        help_text=_("When turned on users can edit their profiles"))
    enable_product_tracking_files = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_('Enable Product Tracking Files'),
        help_text=_("With this setting turned off, the product tracking files will be disabled in the user interface."))
    enable_finding_groups = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_('Enable Finding Groups'),
        help_text=_("With this setting turned off, the Finding Groups will be disabled."))
    enable_calendar = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_('Enable Calendar'),
        help_text=_("With this setting turned off, the Calendar will be disabled in the user interface."))
    default_group = models.ForeignKey(
        'Dojo_Group',
        null=True,
        blank=True,
        help_text=_("New users will be assigned to this group."),
        on_delete=models.RESTRICT)
    default_group_role = models.ForeignKey(
        'Role',
        null=True,
        blank=True,
        help_text=_("New users will be assigned to their default group with this role."),
        on_delete=models.RESTRICT)
    default_group_email_pattern = models.CharField(
        max_length=200,
        default='',
        blank=True,
        help_text=_("New users will only be assigned to the default group, when their email address matches this regex pattern. This is optional condition."))
    minimum_password_length = models.IntegerField(
        default=9,
        verbose_name=_('Minimum password length'),
        help_text=_("Requires user to set passwords greater than minimum length."))
    maximum_password_length = models.IntegerField(
        default=48,
        verbose_name=_('Maximum password length'),
        help_text=_("Requires user to set passwords less than maximum length."))
    number_character_required = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Password must contain one digit"),
        help_text=_("Requires user passwords to contain at least one digit (0-9)."))
    special_character_required = models.BooleanField(
        default=True,
        blank=False,
        verbose_name=_("Password must contain one special character"),
        help_text=_("Requires user passwords to contain at least one special character (()[]{}|\`~!@#$%^&*_-+=;:\'\",<>./?)."))  # noqa W605
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

    from dojo.middleware import System_Settings_Manager
    objects = System_Settings_Manager()


class SystemSettingsFormAdmin(forms.ModelForm):
    product_grade = forms.CharField(widget=forms.Textarea)

    class Meta:
        model = System_Settings
        fields = ['product_grade']


class System_SettingsAdmin(admin.ModelAdmin):
    form = SystemSettingsFormAdmin
    fields = ('product_grade',)
