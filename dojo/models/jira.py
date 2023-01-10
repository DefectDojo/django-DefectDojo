from django import forms
from django.conf import settings
from django.contrib import admin
from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext as _
from dojo.utils import to_str_typed

from . import Finding, Finding_Group, Engagement


class JIRA_Instance(models.Model):
    configuration_name = models.CharField(max_length=2000, help_text=_("Enter a name to give to this configuration"), default='')
    url = models.URLField(max_length=2000, verbose_name=_('JIRA URL'), help_text=_("For more information how to configure Jira, read the DefectDojo documentation."))
    username = models.CharField(max_length=2000)
    password = models.CharField(max_length=2000)

    if hasattr(settings, 'JIRA_ISSUE_TYPE_CHOICES_CONFIG'):
        default_issue_type_choices = settings.JIRA_ISSUE_TYPE_CHOICES_CONFIG
    else:
        default_issue_type_choices = (
                                        ('Task', 'Task'),
                                        ('Story', 'Story'),
                                        ('Epic', 'Epic'),
                                        ('Spike', 'Spike'),
                                        ('Bug', 'Bug'),
                                        ('Security', 'Security')
                                    )
    default_issue_type = models.CharField(max_length=15,
                                          choices=default_issue_type_choices,
                                          default='Bug',
                                          help_text=_('You can define extra issue types in settings.py'))
    issue_template_dir = models.CharField(max_length=255,
                                      null=True,
                                      blank=True,
                                      help_text=_("Choose the folder containing the Django templates used to render the JIRA issue description. These are stored in dojo/templates/issue-trackers. Leave empty to use the default jira_full templates."))
    epic_name_id = models.IntegerField(help_text=_("To obtain the 'Epic name id' visit https://<YOUR JIRA URL>/rest/api/2/field and search for Epic Name. Copy the number out of cf[number] and paste it here."))
    open_status_key = models.IntegerField(verbose_name=_('Reopen Transition ID'), help_text=_("Transition ID to Re-Open JIRA issues, visit https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand=transitions.fields to find the ID for your JIRA instance"))
    close_status_key = models.IntegerField(verbose_name=_('Close Transition ID'), help_text=_("Transition ID to Close JIRA issues, visit https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand=transitions.fields to find the ID for your JIRA instance"))
    info_mapping_severity = models.CharField(max_length=200, help_text=_("Maps to the 'Priority' field in Jira. For example: Info"))
    low_mapping_severity = models.CharField(max_length=200, help_text=_("Maps to the 'Priority' field in Jira. For example: Low"))
    medium_mapping_severity = models.CharField(max_length=200, help_text=_("Maps to the 'Priority' field in Jira. For example: Medium"))
    high_mapping_severity = models.CharField(max_length=200, help_text=_("Maps to the 'Priority' field in Jira. For example: High"))
    critical_mapping_severity = models.CharField(max_length=200, help_text=_("Maps to the 'Priority' field in Jira. For example: Critical"))
    finding_text = models.TextField(null=True, blank=True, help_text=_("Additional text that will be added to the finding in Jira. For example including how the finding was created or who to contact for more information."))
    accepted_mapping_resolution = models.CharField(null=True, blank=True, max_length=300, help_text=_('JIRA resolution names (comma-separated values) that maps to an Accepted Finding'))
    false_positive_mapping_resolution = models.CharField(null=True, blank=True, max_length=300, help_text=_('JIRA resolution names (comma-separated values) that maps to a False Positive Finding'))
    global_jira_sla_notification = models.BooleanField(default=True, blank=False, verbose_name=_("Globally send SLA notifications as comment?"), help_text=_("This setting can be overidden at the Product level"))

    @property
    def accepted_resolutions(self):
        return [m.strip() for m in (self.accepted_mapping_resolution or '').split(',')]

    @property
    def false_positive_resolutions(self):
        return [m.strip() for m in (self.false_positive_mapping_resolution or '').split(',')]

    def __str__(self):
        return self.configuration_name + " | " + self.url + " | " + self.username

    def get_priority(self, status):
        if status == 'Info':
            return self.info_mapping_severity
        elif status == 'Low':
            return self.low_mapping_severity
        elif status == 'Medium':
            return self.medium_mapping_severity
        elif status == 'High':
            return self.high_mapping_severity
        elif status == 'Critical':
            return self.critical_mapping_severity
        else:
            return 'N/A'


# declare form here as we can't import forms.py due to circular imports not even locally
class JIRAForm_Admin(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, required=True)

    # django doesn't seem to have an easy way to handle password fields as PasswordInput requires reentry of passwords
    password_from_db = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance:
            # keep password from db to use if the user entered no password
            self.password_from_db = self.instance.password
            self.fields['password'].required = False

    def clean(self):
        cleaned_data = super().clean()
        if not cleaned_data['password']:
            cleaned_data['password'] = self.password_from_db

        return cleaned_data


class JIRA_Instance_Admin(admin.ModelAdmin):
    form = JIRAForm_Admin


class JIRA_Project(models.Model):
    jira_instance = models.ForeignKey(JIRA_Instance, verbose_name=_('JIRA Instance'),
                             null=True, blank=True, on_delete=models.PROTECT)
    project_key = models.CharField(max_length=200, blank=True)
    product = models.ForeignKey('Product', on_delete=models.CASCADE, null=True)
    issue_template_dir = models.CharField(max_length=255,
                                      null=True,
                                      blank=True,
                                      help_text=_("Choose the folder containing the Django templates used to render the JIRA issue description. These are stored in dojo/templates/issue-trackers. Leave empty to use the default jira_full templates."))
    engagement = models.OneToOneField('Engagement', on_delete=models.CASCADE, null=True, blank=True)
    component = models.CharField(max_length=200, blank=True)
    custom_fields = models.JSONField(max_length=200, blank=True, null=True,
                                   help_text=_("JIRA custom field JSON mapping of Id to value, e.g. {\"customfield_10122\": [{\"name\": \"8.0.1\"}]}"))
    default_assignee = models.CharField(max_length=200, blank=True, null=True,
                                     help_text=_("JIRA default assignee (name). If left blank then it defaults to whatever is configured in JIRA."))
    jira_labels = models.CharField(max_length=200, blank=True, null=True,
                                   help_text=_('JIRA issue labels space seperated'))
    add_vulnerability_id_to_jira_label = models.BooleanField(default=False,
                                                             verbose_name=_('Add vulnerability Id as a JIRA label'),
                                                             blank=False)
    push_all_issues = models.BooleanField(default=False, blank=True,
         help_text=_("Automatically maintain parity with JIRA. Always create and update JIRA tickets for findings in this Product."))
    enable_engagement_epic_mapping = models.BooleanField(default=False,
                                                         blank=True)
    push_notes = models.BooleanField(default=False, blank=True)
    product_jira_sla_notification = models.BooleanField(default=False, blank=True, verbose_name=_("Send SLA notifications as comment?"))
    risk_acceptance_expiration_notification = models.BooleanField(default=False, blank=True, verbose_name=_("Send Risk Acceptance expiration notifications as comment?"))

    def clean(self):
        if not self.jira_instance:
            raise ValidationError('Cannot save JIRA Project Configuration without JIRA Instance')

    def __str__(self):
        return ('%s: ' + self.project_key + '(%s)') % (str(self.id), str(self.jira_instance.url) if self.jira_instance else 'None')


# declare form here as we can't import forms.py due to circular imports not even locally
class JIRAForm_Admin(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, required=True)

    # django doesn't seem to have an easy way to handle password fields as PasswordInput requires reentry of passwords
    password_from_db = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance:
            # keep password from db to use if the user entered no password
            self.password_from_db = self.instance.password
            self.fields['password'].required = False

    def clean(self):
        cleaned_data = super().clean()
        if not cleaned_data['password']:
            cleaned_data['password'] = self.password_from_db

        return cleaned_data


class JIRA_Conf_Admin(admin.ModelAdmin):
    form = JIRAForm_Admin


class JIRA_Issue(models.Model):
    jira_project = models.ForeignKey(JIRA_Project, on_delete=models.CASCADE, null=True)
    jira_id = models.CharField(max_length=200)
    jira_key = models.CharField(max_length=200)
    finding = models.OneToOneField('Finding', null=True, blank=True, on_delete=models.CASCADE)
    engagement = models.OneToOneField('Engagement', null=True, blank=True, on_delete=models.CASCADE)
    finding_group = models.OneToOneField('Finding_Group', null=True, blank=True, on_delete=models.CASCADE)

    jira_creation = models.DateTimeField(editable=True,
                                         null=True,
                                         verbose_name=_('Jira creation'),
                                         help_text=_("The date a Jira issue was created from this finding."))
    jira_change = models.DateTimeField(editable=True,
                                       null=True,
                                       verbose_name=_('Jira last update'),
                                       help_text=_("The date the linked Jira issue was last modified."))

    def set_obj(self, obj):
        if type(obj) == Finding:
            self.finding = obj
        elif type(obj) == Finding_Group:
            self.finding_group = obj
        elif type(obj) == Engagement:
            self.engagement = obj
        else:
            raise ValueError('unknown objec type whiel creating JIRA_Issue: %s' % to_str_typed(obj))

    def __str__(self):
        text = ""
        if self.finding:
            text = self.finding.test.engagement.product.name + " | Finding: " + self.finding.title + ", ID: " + str(self.finding.id)
        elif self.engagement:
            text = self.engagement.product.name + " | Engagement: " + self.engagement.name + ", ID: " + str(self.engagement.id)
        return text + " | Jira Key: " + str(self.jira_key)
