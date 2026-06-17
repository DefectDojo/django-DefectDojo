import logging
import os
from pathlib import Path

from django import forms
from django.conf import settings
from django.core import validators
from django.core.exceptions import ValidationError
from django.urls import reverse

from dojo.jira import services as jira_services
from dojo.models import (
    JIRA_Instance,
    JIRA_Issue,
    JIRA_Project,
)
from dojo.utils import (
    get_system_setting,
    is_finding_groups_enabled,
)

logger = logging.getLogger(__name__)


def get_jira_issue_template_dir_choices():
    template_root = settings.JIRA_TEMPLATE_ROOT
    template_dir_list = [("", "---")]
    for base_dir, dirnames, _filenames in os.walk(template_root):
        # for filename in filenames:
        #     if base_dir.startswith(settings.TEMPLATE_DIR_PREFIX):
        #         base_dir = base_dir[len(settings.TEMPLATE_DIR_PREFIX):]
        #     template_list.append((os.path.join(base_dir, filename), filename))

        for dirname in dirnames:
            clean_base_dir = base_dir.removeprefix(settings.TEMPLATE_DIR_PREFIX)
            template_dir_list.append((str(Path(clean_base_dir) / dirname), dirname))

    logger.debug("templates: %s", template_dir_list)
    return template_dir_list


JIRA_TEMPLATE_CHOICES = sorted(get_jira_issue_template_dir_choices())


class JIRA_IssueForm(forms.ModelForm):

    class Meta:
        model = JIRA_Issue
        exclude = ["product"]


class BaseJiraForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, required=True, help_text=JIRA_Instance._meta.get_field("password").help_text, label=JIRA_Instance._meta.get_field("password").verbose_name)

    def test_jira_connection(self):
        try:
            # Attempt to validate the credentials before moving forward
            jira_services.get_connection_raw(self.cleaned_data["url"],
                                                self.cleaned_data["username"],
                                                self.cleaned_data["password"])
            logger.debug("valid JIRA config!")
        except Exception as e:
            # form only used by admins, so we can show full error message using str(e) which can help debug any problems
            message = "Unable to authenticate to JIRA. Please check the URL, username, password, captcha challenge, Network connection. Details in alert on top right. " + str(
                e)
            self.add_error("username", message)
            self.add_error("password", message)

    def clean(self):
        self.test_jira_connection()
        return self.cleaned_data


class AdvancedJIRAForm(BaseJiraForm):
    issue_template_dir = forms.ChoiceField(required=False,
                                       choices=JIRA_TEMPLATE_CHOICES,
                                       help_text="Choose the folder containing the Django templates used to render the JIRA issue description. These are stored in dojo/templates/issue-trackers. Leave empty to use the default jira_full templates.")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance:
            self.fields["password"].required = False

    def clean(self):
        if self.instance and not self.cleaned_data["password"]:
            self.cleaned_data["password"] = self.instance.password
        return super().clean()

    class Meta:
        model = JIRA_Instance
        exclude = [""]


class JIRAForm(BaseJiraForm):
    issue_key = forms.CharField(required=True, help_text="A valid issue ID is required to gather the necessary information.")
    issue_template_dir = forms.ChoiceField(required=False,
                                       choices=JIRA_TEMPLATE_CHOICES,
                                       help_text="Choose the folder containing the Django templates used to render the JIRA issue description. These are stored in dojo/templates/issue-trackers. Leave empty to use the default jira_full templates.")

    class Meta:
        model = JIRA_Instance
        exclude = ["product", "epic_name_id", "open_status_key",
                    "close_status_key", "info_mapping_severity",
                    "low_mapping_severity", "medium_mapping_severity",
                    "high_mapping_severity", "critical_mapping_severity", "finding_text"]


class DeleteJIRAInstanceForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = JIRA_Instance
        fields = ["id"]


class JIRAProjectForm(forms.ModelForm):
    inherit_from_product = forms.BooleanField(label="inherit JIRA settings from product", required=False)
    jira_instance = forms.ModelChoiceField(queryset=JIRA_Instance.objects.all(), label="JIRA Instance", required=False)
    issue_template_dir = forms.ChoiceField(required=False,
                                       choices=JIRA_TEMPLATE_CHOICES,
                                       help_text="Choose the folder containing the Django templates used to render the JIRA issue description. These are stored in dojo/templates/issue-trackers. Leave empty to use the default jira_full templates.")

    prefix = "jira-project-form"

    class Meta:
        model = JIRA_Project
        exclude = ["product", "engagement"]
        fields = ["inherit_from_product", "jira_instance", "project_key", "issue_template_dir", "epic_issue_type_name", "component", "custom_fields", "jira_labels", "default_assignee", "enabled", "add_vulnerability_id_to_jira_label", "push_all_issues", "enable_engagement_epic_mapping", "push_notes", "product_jira_sla_notification", "risk_acceptance_expiration_notification"]

    def __init__(self, *args, **kwargs):
        # if the form is shown for an engagement, we set a placeholder text around inherited settings from product
        self.target = kwargs.pop("target", "product")
        self.product = kwargs.pop("product", None)
        self.engagement = kwargs.pop("engagement", None)
        super().__init__(*args, **kwargs)

        logger.debug("self.target: %s, self.product: %s, self.instance: %s", self.target, self.product, self.instance)
        logger.debug("data: %s", self.data)
        if self.target == "engagement":
            product_name = self.product.name if self.product else self.engagement.product.name if self.engagement.product else ""

            self.fields["project_key"].widget = forms.TextInput(attrs={"placeholder": f"JIRA settings inherited from product '{product_name}'"})
            self.fields["project_key"].help_text = f"JIRA settings are inherited from product '{product_name}', unless configured differently here."
            self.fields["jira_instance"].help_text = f"JIRA settings are inherited from product '{product_name}' , unless configured differently here."

            # if we don't have an instance, django will insert a blank empty one :-(
            # so we have to check for id to make sure we only trigger this when there is a real instance from db
            if self.instance.id:
                logger.debug("jira project instance found for engagement, unchecking inherit checkbox")
                self.fields["jira_instance"].required = True
                self.fields["project_key"].required = True
                self.initial["inherit_from_product"] = False
                # once a jira project config is attached to an engagement, we can't go back to inheriting
                # because the config needs to remain in place for the existing jira issues
                self.fields["inherit_from_product"].disabled = True
                self.fields["inherit_from_product"].help_text = "Once an engagement has a JIRA Project stored, you cannot switch back to inheritance to avoid breaking existing JIRA issues"
                self.fields["jira_instance"].disabled = False
                self.fields["project_key"].disabled = False
                self.fields["issue_template_dir"].disabled = False
                self.fields["epic_issue_type_name"].disabled = False
                self.fields["component"].disabled = False
                self.fields["custom_fields"].disabled = False
                self.fields["default_assignee"].disabled = False
                self.fields["jira_labels"].disabled = False
                self.fields["enabled"].disabled = False
                self.fields["add_vulnerability_id_to_jira_label"].disabled = False
                self.fields["push_all_issues"].disabled = False
                self.fields["enable_engagement_epic_mapping"].disabled = False
                self.fields["push_notes"].disabled = False
                self.fields["product_jira_sla_notification"].disabled = False
                self.fields["risk_acceptance_expiration_notification"].disabled = False

            elif self.product:
                logger.debug("setting jira project fields from product1")
                self.initial["inherit_from_product"] = True
                jira_project_product = jira_services.get_project(self.product)
                # we have to check that we are not in a POST request where jira project config data is posted
                # this is because initial values will overwrite the actual values entered by the user
                # makes no sense, but seems to be accepted behaviour: https://code.djangoproject.com/ticket/30407
                if jira_project_product and (self.prefix + "-jira_instance") not in self.data:
                    logger.debug("setting jira project fields from product2")
                    self.initial["jira_instance"] = jira_project_product.jira_instance.id if jira_project_product.jira_instance else None
                    self.initial["project_key"] = jira_project_product.project_key
                    self.initial["issue_template_dir"] = jira_project_product.issue_template_dir
                    self.initial["epic_issue_type_name"] = jira_project_product.epic_issue_type_name
                    self.initial["component"] = jira_project_product.component
                    self.initial["custom_fields"] = jira_project_product.custom_fields
                    self.initial["default_assignee"] = jira_project_product.default_assignee
                    self.initial["jira_labels"] = jira_project_product.jira_labels
                    self.initial["enabled"] = jira_project_product.enabled
                    self.initial["add_vulnerability_id_to_jira_label"] = jira_project_product.add_vulnerability_id_to_jira_label
                    self.initial["push_all_issues"] = jira_project_product.push_all_issues
                    self.initial["enable_engagement_epic_mapping"] = jira_project_product.enable_engagement_epic_mapping
                    self.initial["push_notes"] = jira_project_product.push_notes
                    self.initial["product_jira_sla_notification"] = jira_project_product.product_jira_sla_notification
                    self.initial["risk_acceptance_expiration_notification"] = jira_project_product.risk_acceptance_expiration_notification

                    self.fields["jira_instance"].disabled = True
                    self.fields["project_key"].disabled = True
                    self.fields["issue_template_dir"].disabled = True
                    self.fields["epic_issue_type_name"].disabled = True
                    self.fields["component"].disabled = True
                    self.fields["custom_fields"].disabled = True
                    self.fields["default_assignee"].disabled = True
                    self.fields["jira_labels"].disabled = True
                    self.fields["enabled"].disabled = True
                    self.fields["add_vulnerability_id_to_jira_label"].disabled = True
                    self.fields["push_all_issues"].disabled = True
                    self.fields["enable_engagement_epic_mapping"].disabled = True
                    self.fields["push_notes"].disabled = True
                    self.fields["product_jira_sla_notification"].disabled = True
                    self.fields["risk_acceptance_expiration_notification"].disabled = True

        else:
            del self.fields["inherit_from_product"]

        # if we don't have an instance, django will insert a blank empty one :-(
        # so we have to check for id to make sure we only trigger this when there is a real instance from db
        if self.instance.id:
            self.fields["jira_instance"].required = True
            self.fields["project_key"].required = True
            self.fields["epic_issue_type_name"].required = True

    def clean(self):
        logger.debug("validating jira project form")
        cleaned_data = super().clean()

        logger.debug("clean: inherit: %s", self.cleaned_data.get("inherit_from_product", False))
        if not self.cleaned_data.get("inherit_from_product", False):
            jira_instance = self.cleaned_data.get("jira_instance")
            project_key = self.cleaned_data.get("project_key")
            epic_issue_type_name = self.cleaned_data.get("epic_issue_type_name")

            if project_key and jira_instance and epic_issue_type_name:
                return cleaned_data

            if not project_key and not jira_instance and not epic_issue_type_name:
                return cleaned_data

            if self.target == "engagement":
                msg = "JIRA Project needs a JIRA Instance, JIRA Project Key, and Epic issue type name, or choose to inherit settings from product"
                raise ValidationError(msg)
            msg = "JIRA Project needs a JIRA Instance, JIRA Project Key, and Epic issue type name, leave empty to have no JIRA integration setup"
            raise ValidationError(msg)
        return None


class JIRAFindingForm(forms.Form):
    def __init__(self, *args, **kwargs):
        self.push_all = kwargs.pop("push_all", False)
        self.instance = kwargs.pop("instance", None)
        self.jira_project = kwargs.pop("jira_project", None)
        # we provide the finding_form from the same page so we can add validation errors
        # if the finding doesn't satisfy the rules to be pushed to JIRA
        self.finding_form = kwargs.pop("finding_form", None)

        if self.instance is None and self.jira_project is None:
            msg = "either and finding instance or jira_project is needed"
            raise ValueError(msg)

        super().__init__(*args, **kwargs)
        self.fields["push_to_jira"] = forms.BooleanField()
        self.fields["push_to_jira"].required = False
        if is_finding_groups_enabled():
            self.fields["push_to_jira"].help_text = "Checking this will overwrite content of your JIRA issue, or create one. If this finding is part of a Finding Group, the group will pushed instead of the finding."
        else:
            self.fields["push_to_jira"].help_text = "Checking this will overwrite content of your JIRA issue, or create one."

        self.fields["push_to_jira"].label = "Push to JIRA"
        if self.push_all:
            # This will show the checkbox as checked and greyed out, this way the user is aware
            # that issues will be pushed to JIRA, given their product-level settings.
            self.fields["push_to_jira"].help_text = (
                "Push all issues is enabled on this product. If you do not wish to push all issues"
                " to JIRA, please disable Push all issues on this product."
            )
            self.fields["push_to_jira"].widget.attrs["checked"] = "checked"
            self.fields["push_to_jira"].disabled = True

        if self.instance:
            if hasattr(self.instance, "has_jira_issue") and self.instance.has_jira_issue:
                self.initial["jira_issue"] = self.instance.jira_issue.jira_key
                self.fields["push_to_jira"].widget.attrs["checked"] = "checked"
        if is_finding_groups_enabled():
            self.fields["jira_issue"].widget = forms.TextInput(attrs={"placeholder": "Leave empty and check push to jira to create a new JIRA issue for this finding, or the group this finding is in."})
        else:
            self.fields["jira_issue"].widget = forms.TextInput(attrs={"placeholder": "Leave empty and check push to jira to create a new JIRA issue for this finding."})

        if self.instance and hasattr(self.instance, "has_jira_group_issue") and self.instance.has_jira_group_issue:
            self.fields["push_to_jira"].widget.attrs["checked"] = "checked"
            self.fields["jira_issue"].help_text = "Changing the linked JIRA issue for finding groups is not (yet) supported."
            self.initial["jira_issue"] = self.instance.finding_group.jira_issue.jira_key
            self.fields["jira_issue"].disabled = True

    def clean(self):
        logger.debug("jform clean")
        super().clean()
        jira_issue_key_new = self.cleaned_data.get("jira_issue")
        finding = self.instance
        jira_project = self.jira_project

        logger.debug("self.cleaned_data.push_to_jira: %s", self.cleaned_data.get("push_to_jira", None))

        if self.cleaned_data.get("push_to_jira", None) and finding and finding.has_jira_group_issue:
            can_be_pushed_to_jira, error_message, error_code = jira_services.can_be_pushed(finding.finding_group, self.finding_form)
            if not can_be_pushed_to_jira:
                self.add_error("push_to_jira", ValidationError(error_message, code=error_code))
                # for field in error_fields:
                #     self.finding_form.add_error(field, error)

        elif self.cleaned_data.get("push_to_jira", None) and finding:
            can_be_pushed_to_jira, error_message, error_code = jira_services.can_be_pushed(finding, self.finding_form)
            if not can_be_pushed_to_jira:
                self.add_error("push_to_jira", ValidationError(error_message, code=error_code))
                # for field in error_fields:
                #     self.finding_form.add_error(field, error)
        elif self.cleaned_data.get("push_to_jira", None):
            active = self.finding_form["active"].value()
            verified = self.finding_form["verified"].value()
            if not active or (not verified and (get_system_setting("enforce_verified_status", True) or get_system_setting("enforce_verified_status_jira", True))):
                logger.debug("Findings must be active and verified to be pushed to JIRA")
                error_message = "Findings must be active and verified to be pushed to JIRA"
                self.add_error("push_to_jira", ValidationError(error_message, code="not_active_or_verified"))

        if jira_issue_key_new and (not finding or not finding.has_jira_group_issue):
            # when there is a group jira issue, we skip all the linking/unlinking as this is not supported (yet)
            if finding:
                # in theory there can multiple jira instances that have similar projects
                # so checking by only the jira issue key can lead to false positives
                # so we check also the jira internal id of the jira issue
                # if the key and id are equal, it is probably the same jira instance and the same issue
                # the database model is lacking some relations to also include the jira config name or url here
                # and I don't want to change too much now. this should cover most usecases.

                jira_issue_need_to_exist = False
                # changing jira link on finding
                if finding.has_jira_issue and jira_issue_key_new != finding.jira_issue.jira_key:
                    jira_issue_need_to_exist = True

                # adding existing jira issue to finding without jira link
                if not finding.has_jira_issue:
                    jira_issue_need_to_exist = True

            else:
                jira_issue_need_to_exist = True

            if jira_issue_need_to_exist:
                jira_issue_new = jira_services.jira_get_issue(jira_project, jira_issue_key_new)
                if not jira_issue_new:
                    raise ValidationError("JIRA issue " + jira_issue_key_new + " does not exist or cannot be retrieved")

                logger.debug("checking if provided jira issue id already is linked to another finding")
                jira_issues = JIRA_Issue.objects.filter(jira_id=jira_issue_new.id, jira_key=jira_issue_key_new).exclude(engagement__isnull=False)

                if self.instance:
                    # just be sure we exclude the finding that is being edited
                    jira_issues = jira_issues.exclude(finding=finding)

                if len(jira_issues) > 0:
                    raise ValidationError("JIRA issue " + jira_issue_key_new + " already linked to " + reverse("view_finding", args=(jira_issues[0].finding_id,)))

    jira_issue = forms.CharField(required=False, label="Linked JIRA Issue",
                validators=[validators.RegexValidator(
                    regex=r"^[A-Z][A-Z_0-9]+-\d+$",
                    message="JIRA issue key must be in XXXX-nnnn format ([A-Z][A-Z_0-9]+-\\d+)")])
    push_to_jira = forms.BooleanField(required=False, label="Push to JIRA")


class JIRAImportScanForm(forms.Form):
    def __init__(self, *args, **kwargs):
        self.push_all = kwargs.pop("push_all", False)

        super().__init__(*args, **kwargs)
        if self.push_all:
            # This will show the checkbox as checked and greyed out, this way the user is aware
            # that issues will be pushed to JIRA, given their product-level settings.
            self.fields["push_to_jira"].help_text = (
                "Push all issues is enabled on this product. If you do not wish to push all issues"
                " to JIRA, please disable Push all issues on this product."
            )
            self.fields["push_to_jira"].widget.attrs["checked"] = "checked"
            self.fields["push_to_jira"].disabled = True

    push_to_jira = forms.BooleanField(required=False, label="Push to JIRA", help_text="Checking this will create a new jira issue for each new finding.")


class JIRAEngagementForm(forms.Form):
    prefix = "jira-epic-form"

    def __init__(self, *args, **kwargs):
        self.instance = kwargs.pop("instance", None)

        super().__init__(*args, **kwargs)

        if self.instance:
            if self.instance.has_jira_issue:
                self.fields["push_to_jira"].widget.attrs["checked"] = "checked"
                self.fields["push_to_jira"].label = "Update JIRA Epic"
                self.fields["push_to_jira"].help_text = "Checking this will update the existing EPIC in JIRA."

    push_to_jira = forms.BooleanField(required=False, label="Create EPIC", help_text="Checking this will create an EPIC in JIRA for this engagement.")
    epic_name = forms.CharField(max_length=200, required=False, help_text="EPIC name in JIRA. If not specified, it defaults to the engagement name")
    epic_priority = forms.CharField(max_length=200, required=False, help_text="EPIC priority. If not specified, the JIRA default priority will be used")
