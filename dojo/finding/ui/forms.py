import tagulous
from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _
from tagulous.forms import TagField

from dojo.endpoint.utils import validate_endpoints_to_add
from dojo.finding.queries import get_authorized_findings
from dojo.finding.vulnerability_id import cwe_number, parse_cwes
from dojo.jira import services as jira_services
from dojo.location.models import Location
from dojo.location.utils import validate_locations_to_add
from dojo.models import (
    EFFORT_FOR_FIXING_CHOICES,
    SEVERITY_CHOICES,
    Dojo_User,
    Endpoint,
    Finding,
    Finding_Group,
    Finding_Template,
    Notes,
    Risk_Acceptance,
    Test,
)
from dojo.user.queries import get_authorized_users, get_authorized_users_for_product_and_product_type
from dojo.utils import get_system_setting, is_finding_groups_enabled
from dojo.validators import cvss3_validator, cvss4_validator, tag_validator
from dojo.widgets import TableCheckboxWidget

CVSS_CALCULATOR_URLS = {
        "https://www.first.org/cvss/calculator/3-0": "CVSS3 Calculator by FIRST",
        "https://www.first.org/cvss/calculator/4-0": "CVSS4 Calculator by FIRST",
        "https://www.metaeffekt.com/security/cvss/calculator/": "CVSS2/3/4 Calculator by Metaeffekt",
    }


vulnerability_ids_field = forms.CharField(max_length=5000,
    required=False,
    label="Vulnerability Ids",
    help_text="Ids of vulnerabilities in security advisories associated with this finding. Can be Common Vulnerabilities and Exposures (CVE) or from other sources."
                "You may enter one vulnerability id per line.",
    widget=forms.widgets.Textarea(attrs={"rows": "3", "cols": "400"}))

cwes_field = forms.CharField(max_length=500,
    required=False,
    label="CWEs",
    help_text="CWE numbers associated with this finding. You may enter one per line (e.g. 89 or CWE-89). The first is the primary CWE.",
    widget=forms.widgets.Textarea(attrs={"rows": "3", "cols": "400"}))


class CweFormMixin:

    """
    Persist the 'cwes' textarea as the primary Finding.cwe plus extra Finding_CWE rows.

    Mirrors how the 'vulnerability_ids' textarea maps to cve + Vulnerability_Id rows.
    """

    def clean_cwes(self):
        value = self.cleaned_data.get("cwes", "")
        invalid = [token for token in value.replace(",", "\n").split() if cwe_number(token) is None]
        if invalid:
            msg = f"Invalid CWE(s): {', '.join(invalid)}. Enter numbers like 89 or CWE-89, one per line."
            raise forms.ValidationError(msg)
        return value

    def save(self, commit=True):  # noqa: FBT002
        cwes = parse_cwes(self.cleaned_data.get("cwes"))
        self.instance.cwe = cwe_number(cwes[0]) if cwes else 0
        self.instance.unsaved_cwes = cwes[1:]
        return super().save(commit=commit)


EFFORT_FOR_FIXING_INVALID_CHOICE = _("Select valid choice: Low,Medium,High")


class BulletListDisplayWidget(forms.Widget):
    def __init__(self, urls_dict=None, *args, **kwargs):
        self.urls_dict = urls_dict or {}
        super().__init__(*args, **kwargs)

    def render(self, name, value, attrs=None, renderer=None):
        if not self.urls_dict:
            return ""

        html = '<ul style="margin: 0; padding-left: 20px;">'
        for url, text in self.urls_dict.items():
            html += f'<li style="list-style-type: disc;"><a href="{url}" target="_blank"><i class="fa fa-arrow-up-right-from-square" style="margin-right: 5px;"></i>{text}</a></li>'
        html += "</ul>"
        return mark_safe(html)


def hide_cvss_fields_if_disabled(form_instance):
    """Hide CVSS fields based on system settings."""
    enable_cvss3 = get_system_setting("enable_cvss3_display", True)
    enable_cvss4 = get_system_setting("enable_cvss4_display", True)

    # Hide CVSS3 fields if disabled
    if not enable_cvss3:
        if "cvssv3" in form_instance.fields:
            del form_instance.fields["cvssv3"]
        if "cvssv3_score" in form_instance.fields:
            del form_instance.fields["cvssv3_score"]

    # Hide CVSS4 fields if disabled
    if not enable_cvss4:
        if "cvssv4" in form_instance.fields:
            del form_instance.fields["cvssv4"]
        if "cvssv4_score" in form_instance.fields:
            del form_instance.fields["cvssv4_score"]

    # If both are disabled, hide all CVSS related fields
    if not enable_cvss3 and not enable_cvss4:
        if "cvss_info" in form_instance.fields:
            del form_instance.fields["cvss_info"]


class EditFindingGroupForm(forms.ModelForm):
    name = forms.CharField(max_length=255, required=True, label="Finding Group Name")
    jira_issue = forms.CharField(max_length=255, required=False, label="Linked JIRA Issue",
                                 help_text="Leave empty and check push to jira to create a new JIRA issue for this finding group.")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["push_to_jira"] = forms.BooleanField()
        self.fields["push_to_jira"].required = False
        self.fields["push_to_jira"].help_text = "Checking this will overwrite content of your JIRA issue, or create one."

        self.fields["push_to_jira"].label = "Push to JIRA"

        if hasattr(self.instance, "has_jira_issue") and self.instance.has_jira_issue:
            jira_url = jira_services.get_url(self.instance)
            self.fields["jira_issue"].initial = jira_url
            self.fields["push_to_jira"].widget.attrs["checked"] = "checked"

    class Meta:
        model = Finding_Group
        fields = ["name"]


class DeleteFindingGroupForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Finding_Group
        fields = ["id"]


class MergeFindings(forms.ModelForm):
    FINDING_ACTION = (("", "Select an Action"), ("inactive", "Inactive"), ("delete", "Delete"))

    append_description = forms.BooleanField(label="Append Description", initial=True, required=False,
                                            help_text="Description in all findings will be appended into the merged finding.")

    add_endpoints = forms.BooleanField(label="Add Endpoints", initial=True, required=False,
                                           help_text="Endpoints in all findings will be merged into the merged finding.")

    dynamic_raw = forms.BooleanField(label="Dynamic Scanner Raw Requests", initial=True, required=False,
                                           help_text="Dynamic scanner raw requests in all findings will be merged into the merged finding.")

    tag_finding = forms.BooleanField(label="Add Tags", initial=True, required=False,
                                           help_text="Tags in all findings will be merged into the merged finding.")

    mark_tag_finding = forms.BooleanField(label="Tag Merged Finding", initial=True, required=False,
                                           help_text="Creates a tag titled 'merged' for the finding that will be merged. If the 'Finding Action' is set to 'inactive' the inactive findings will be tagged with 'merged-inactive'.")

    append_reference = forms.BooleanField(label="Append Reference", initial=True, required=False,
                                            help_text="Reference in all findings will be appended into the merged finding.")

    finding_action = forms.ChoiceField(
        required=True,
        choices=FINDING_ACTION,
        label="Finding Action",
        help_text="The action to take on the merged finding. Set the findings to inactive or delete the findings.")

    def __init__(self, *args, **kwargs):
        _ = kwargs.pop("finding")
        findings = kwargs.pop("findings")
        super().__init__(*args, **kwargs)

        self.fields["finding_to_merge_into"] = forms.ModelChoiceField(
            queryset=findings, initial=0, required="False", label="Finding to Merge Into", help_text="Findings selected below will be merged into this finding.")

        # Exclude the finding to merge into from the findings to merge into
        self.fields["findings_to_merge"] = forms.ModelMultipleChoiceField(
            queryset=findings, required=True, label="Findings to Merge",
            widget=forms.widgets.SelectMultiple(attrs={"size": 10}),
            help_text=("Select the findings to merge."))
        self.field_order = ["finding_to_merge_into", "findings_to_merge", "append_description", "add_endpoints", "append_reference"]

    class Meta:
        model = Finding
        fields = ["append_description", "add_endpoints", "append_reference"]


class AddFindingsRiskAcceptanceForm(forms.ModelForm):

    accepted_findings = forms.ModelMultipleChoiceField(
        queryset=Finding.objects.none(),
        required=True,
        label="",
        widget=TableCheckboxWidget(attrs={"size": 25}),
    )

    class Meta:
        model = Risk_Acceptance
        fields = ["accepted_findings"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["accepted_findings"].queryset = get_authorized_findings("edit")


class AddFindingForm(CweFormMixin, forms.ModelForm):
    title = forms.CharField(max_length=1000)
    date = forms.DateField(required=True,
                           widget=forms.TextInput(attrs={"class": "datepicker", "autocomplete": "off"}))
    cwes = cwes_field
    vulnerability_ids = vulnerability_ids_field
    cvssv3 = forms.CharField(label="CVSS3 Vector", max_length=117, required=False, widget=forms.TextInput(attrs={"class": "cvsscalculator", "data-toggle": "dropdown", "aria-haspopup": "true", "aria-expanded": "false"}))
    cvssv3_score = forms.FloatField(label="CVSS3 Score", required=False, max_value=10.0, min_value=0.0)
    cvssv4 = forms.CharField(label="CVSS4 Vector", max_length=255, required=False)
    cvssv4_score = forms.FloatField(label="CVSS4 Score", required=False, max_value=10.0, min_value=0.0)
    description = forms.CharField(widget=forms.Textarea)
    severity = forms.ChoiceField(
        choices=SEVERITY_CHOICES,
        error_messages={
            "required": "Select valid choice: In Progress, On Hold, Completed",
            "invalid_choice": EFFORT_FOR_FIXING_INVALID_CHOICE})
    mitigation = forms.CharField(widget=forms.Textarea, required=False)
    impact = forms.CharField(widget=forms.Textarea, required=False)
    request = forms.CharField(widget=forms.Textarea, required=False)
    response = forms.CharField(widget=forms.Textarea, required=False)
    endpoints = forms.ModelMultipleChoiceField(Location.objects.none(), required=False, label="Systems / Endpoints")
    endpoints_to_add = forms.CharField(max_length=5000, required=False, label="Endpoints to add",
                               help_text="The IP address, host name or full URL. You may enter one endpoint per line. "
                                         "Each must be valid.",
                               widget=forms.widgets.Textarea(attrs={"rows": "3", "cols": "400"}))
    references = forms.CharField(widget=forms.Textarea, required=False)
    publish_date = forms.DateField(widget=forms.TextInput(attrs={"class": "datepicker", "autocomplete": "off"}), required=False)
    planned_remediation_date = forms.DateField(widget=forms.TextInput(attrs={"class": "datepicker", "autocomplete": "off"}), required=False)
    planned_remediation_version = forms.CharField(max_length=99, required=False)
    effort_for_fixing = forms.ChoiceField(
        required=False,
        choices=EFFORT_FOR_FIXING_CHOICES,
        error_messages={
            "invalid_choice": EFFORT_FOR_FIXING_INVALID_CHOICE})

    # the only reliable way without hacking internal fields to get predicatble ordering is to make it explicit
    field_order = ("title", "date", "cwes", "vulnerability_ids", "severity", "cvssv3", "cvssv3_score", "cvssv4", "cvssv4_score", "description", "mitigation", "impact", "request", "response", "steps_to_reproduce",
                   "severity_justification", "endpoints", "endpoints_to_add", "references", "active", "verified", "false_p", "duplicate", "out_of_scope",
                   "risk_accepted", "under_defect_review")

    def __init__(self, *args, **kwargs):
        req_resp = kwargs.pop("req_resp")

        product = None
        if "product" in kwargs:
            product = kwargs.pop("product")

        super().__init__(*args, **kwargs)

        if settings.V3_FEATURE_LOCATIONS and product:
            self.fields["endpoints"].queryset = Location.objects.filter(products__product=product)
        # TODO: Delete this after the move to Locations
        elif product:
            self.fields["endpoints"].queryset = Endpoint.objects.filter(product=product)
        else:
            self.fields["endpoints"].queryset = Endpoint.objects.none()

        if req_resp:
            self.fields["request"].initial = req_resp[0]
            self.fields["response"].initial = req_resp[1]

        self.endpoints_to_add_list = []

        # Hide CVSS fields based on system settings
        hide_cvss_fields_if_disabled(self)

    def clean(self):
        cleaned_data = super().clean()
        if ((cleaned_data["active"] or cleaned_data["verified"]) and cleaned_data["duplicate"]):
            msg = "Duplicate findings cannot be verified or active"
            raise forms.ValidationError(msg)
        if cleaned_data["false_p"] and cleaned_data["verified"]:
            msg = "False positive findings cannot be verified."
            raise forms.ValidationError(msg)
        if cleaned_data["active"] and "risk_accepted" in cleaned_data and cleaned_data["risk_accepted"]:
            msg = "Active findings cannot be risk accepted."
            raise forms.ValidationError(msg)

        if settings.V3_FEATURE_LOCATIONS:
            endpoints_to_add_list, errors = validate_locations_to_add(cleaned_data["endpoints_to_add"])
        else:
            # TODO: Delete this after the move to Locations
            endpoints_to_add_list, errors = validate_endpoints_to_add(cleaned_data["endpoints_to_add"])

        if errors:
            raise forms.ValidationError(errors)
        self.endpoints_to_add_list = endpoints_to_add_list

        return cleaned_data

    def clean_tags(self):
        tag_validator(self.cleaned_data.get("tags"))
        return self.cleaned_data.get("tags")

    class Meta:
        model = Finding
        exclude = ("reporter", "url", "numerical_severity", "under_review", "reviewers", "cve", "cwe", "inherited_tags",
                   "review_requested_by", "is_mitigated", "jira_creation", "jira_change", "endpoints", "sla_start_date")


class AdHocFindingForm(CweFormMixin, forms.ModelForm):
    title = forms.CharField(max_length=1000)
    date = forms.DateField(required=True,
                           widget=forms.TextInput(attrs={"class": "datepicker", "autocomplete": "off"}))
    cwes = cwes_field
    vulnerability_ids = vulnerability_ids_field

    cvss_info = forms.CharField(
        label="CVSS",
        widget=BulletListDisplayWidget(CVSS_CALCULATOR_URLS),
        required=False,
        disabled=True)

    cvssv3 = forms.CharField(label="CVSS3 Vector", max_length=117, required=False, widget=forms.TextInput(attrs={"class": "cvsscalculator", "data-toggle": "dropdown", "aria-haspopup": "true", "aria-expanded": "false"}))
    cvssv3_score = forms.FloatField(label="CVSS3 Score", required=False, max_value=10.0, min_value=0.0)
    cvssv4 = forms.CharField(label="CVSS4 Vector", max_length=255, required=False)
    cvssv4_score = forms.FloatField(label="CVSS4 Score", required=False, max_value=10.0, min_value=0.0)
    description = forms.CharField(widget=forms.Textarea)
    severity = forms.ChoiceField(
        choices=SEVERITY_CHOICES,
        error_messages={
            "required": "Select valid choice: In Progress, On Hold, Completed",
            "invalid_choice": EFFORT_FOR_FIXING_INVALID_CHOICE})
    mitigation = forms.CharField(widget=forms.Textarea, required=False)
    impact = forms.CharField(widget=forms.Textarea, required=False)
    request = forms.CharField(widget=forms.Textarea, required=False)
    response = forms.CharField(widget=forms.Textarea, required=False)
    endpoints = forms.ModelMultipleChoiceField(queryset=Location.objects.all(), required=False,
                                               label="Systems / Endpoints")
    endpoints_to_add = forms.CharField(max_length=5000, required=False, label="Endpoints to add",
                                       help_text="The IP address, host name or full URL. You may enter one endpoint per line. "
                                                 "Each must be valid.",
                                       widget=forms.widgets.Textarea(attrs={"rows": "3", "cols": "400"}))
    references = forms.CharField(widget=forms.Textarea, required=False)
    publish_date = forms.DateField(widget=forms.TextInput(attrs={"class": "datepicker", "autocomplete": "off"}), required=False)
    planned_remediation_date = forms.DateField(widget=forms.TextInput(attrs={"class": "datepicker", "autocomplete": "off"}), required=False)
    planned_remediation_version = forms.CharField(max_length=99, required=False)
    effort_for_fixing = forms.ChoiceField(
        required=False,
        choices=EFFORT_FOR_FIXING_CHOICES,
        error_messages={
            "invalid_choice": EFFORT_FOR_FIXING_INVALID_CHOICE})

    # the only reliable way without hacking internal fields to get predicatble ordering is to make it explicit
    field_order = ("title", "date", "cwes", "vulnerability_ids", "severity", "cvss_info", "cvssv3", "cvssv3_score", "cvssv4", "cvssv4_score", "description", "mitigation",
                   "impact", "request", "response", "steps_to_reproduce", "severity_justification", "endpoints", "endpoints_to_add", "references",
                   "active", "verified", "false_p", "duplicate", "out_of_scope", "risk_accepted", "under_defect_review", "sla_start_date", "sla_expiration_date")

    def __init__(self, *args, **kwargs):
        req_resp = kwargs.pop("req_resp")

        product = None
        if "product" in kwargs:
            product = kwargs.pop("product")

        super().__init__(*args, **kwargs)

        if settings.V3_FEATURE_LOCATIONS and product:
            self.fields["endpoints"].queryset = Location.objects.filter(products__product=product)
        # TODO: Delete this after the move to Locations
        elif product:
            self.fields["endpoints"].queryset = Endpoint.objects.filter(product=product)
        else:
            self.fields["endpoints"].queryset = Endpoint.objects.none()

        if req_resp:
            self.fields["request"].initial = req_resp[0]
            self.fields["response"].initial = req_resp[1]

        self.endpoints_to_add_list = []

        # Hide CVSS fields based on system settings
        hide_cvss_fields_if_disabled(self)

    def clean(self):
        cleaned_data = super().clean()
        if ((cleaned_data["active"] or cleaned_data["verified"]) and cleaned_data["duplicate"]):
            msg = "Duplicate findings cannot be verified or active"
            raise forms.ValidationError(msg)
        if cleaned_data["false_p"] and cleaned_data["verified"]:
            msg = "False positive findings cannot be verified."
            raise forms.ValidationError(msg)

        if settings.V3_FEATURE_LOCATIONS:
            endpoints_to_add_list, errors = validate_locations_to_add(cleaned_data["endpoints_to_add"])
        else:
            # TODO: Delete this after the move to Locations
            endpoints_to_add_list, errors = validate_endpoints_to_add(cleaned_data["endpoints_to_add"])

        self.endpoints_to_add_list = endpoints_to_add_list

        if errors:
            raise forms.ValidationError(errors)

        return cleaned_data

    def clean_tags(self):
        tag_validator(self.cleaned_data.get("tags"))
        return self.cleaned_data.get("tags")

    class Meta:
        model = Finding
        exclude = ("reporter", "url", "numerical_severity", "under_review", "reviewers", "cve", "cwe", "inherited_tags",
                   "review_requested_by", "is_mitigated", "jira_creation", "jira_change", "endpoints", "sla_start_date",
                   "sla_expiration_date")


class PromoteFindingForm(CweFormMixin, forms.ModelForm):
    title = forms.CharField(max_length=1000)
    date = forms.DateField(required=True,
                           widget=forms.TextInput(attrs={"class": "datepicker", "autocomplete": "off"}))
    cwes = cwes_field
    vulnerability_ids = vulnerability_ids_field

    cvss_info = forms.CharField(
        label="CVSS",
        widget=BulletListDisplayWidget(CVSS_CALCULATOR_URLS),
        required=False,
        disabled=True)

    cvssv3 = forms.CharField(label="CVSS3 Vector", max_length=117, required=False, widget=forms.TextInput(attrs={"class": "cvsscalculator", "data-toggle": "dropdown", "aria-haspopup": "true", "aria-expanded": "false"}))
    cvssv3_score = forms.FloatField(label="CVSS3 Score", required=False, max_value=10.0, min_value=0.0)
    cvssv4 = forms.CharField(label="CVSS4 Vector", max_length=255, required=False)
    cvssv4_score = forms.FloatField(label="CVSS4 Score", required=False, max_value=10.0, min_value=0.0)
    description = forms.CharField(widget=forms.Textarea)
    severity = forms.ChoiceField(
        choices=SEVERITY_CHOICES,
        error_messages={
            "required": "Select valid choice: In Progress, On Hold, Completed",
            "invalid_choice": "Select valid choice: Critical,High,Medium,Low"})
    mitigation = forms.CharField(widget=forms.Textarea, required=False)
    impact = forms.CharField(widget=forms.Textarea, required=False)
    endpoints = forms.ModelMultipleChoiceField(Location.objects.none(), required=False, label="Systems / Endpoints")
    endpoints_to_add = forms.CharField(max_length=5000, required=False, label="Endpoints to add",
                               help_text="The IP address, host name or full URL. You may enter one endpoint per line. "
                                         "Each must be valid.",
                               widget=forms.widgets.Textarea(attrs={"rows": "3", "cols": "400"}))
    references = forms.CharField(widget=forms.Textarea, required=False)

    # the onyl reliable way without hacking internal fields to get predicatble ordering is to make it explicit
    field_order = ("title", "group", "date", "sla_start_date", "sla_expiration_date", "cwes", "vulnerability_ids", "severity", "cvss_info", "cvssv3",
                   "cvssv3_score", "cvssv4", "cvssv4_score", "description", "mitigation", "impact", "request", "response", "steps_to_reproduce",
                    "severity_justification", "endpoints", "endpoints_to_add", "references", "active", "mitigated", "mitigated_by", "verified",
                    "false_p", "duplicate", "out_of_scope", "risk_accept", "under_defect_review")

    def __init__(self, *args, **kwargs):
        product = None
        if "product" in kwargs:
            product = kwargs.pop("product")

        super().__init__(*args, **kwargs)

        if settings.V3_FEATURE_LOCATIONS and product:
            self.fields["endpoints"].queryset = Location.objects.filter(products__product=product)
        # TODO: Delete this after the move to Locations
        elif product:
            self.fields["endpoints"].queryset = Endpoint.objects.filter(product=product)
        else:
            self.fields["endpoints"].queryset = Endpoint.objects.none()

        self.endpoints_to_add_list = []

        # Hide CVSS fields based on system settings
        hide_cvss_fields_if_disabled(self)

    def clean(self):
        cleaned_data = super().clean()

        if settings.V3_FEATURE_LOCATIONS:
            endpoints_to_add_list, errors = validate_locations_to_add(cleaned_data["endpoints_to_add"])
        else:
            # TODO: Delete this after the move to Locations
            endpoints_to_add_list, errors = validate_endpoints_to_add(cleaned_data["endpoints_to_add"])

        if errors:
            raise forms.ValidationError(errors)
        self.endpoints_to_add_list = endpoints_to_add_list

        return cleaned_data

    def clean_tags(self):
        tag_validator(self.cleaned_data.get("tags"))
        return self.cleaned_data.get("tags")

    class Meta:
        model = Finding
        exclude = ("reporter", "url", "numerical_severity", "active", "false_p", "verified", "endpoint_status", "cve", "cwe", "inherited_tags",
                   "duplicate", "out_of_scope", "under_review", "reviewers", "review_requested_by", "is_mitigated", "jira_creation", "jira_change", "planned_remediation_date", "planned_remediation_version", "effort_for_fixing")


class FindingForm(CweFormMixin, forms.ModelForm):
    title = forms.CharField(max_length=1000)
    group = forms.ModelChoiceField(required=False, queryset=Finding_Group.objects.none(), help_text="The Finding Group to which this finding belongs, leave empty to remove the finding from the group. Groups can only be created via Bulk Edit for now.")
    date = forms.DateField(required=True,
                           widget=forms.TextInput(attrs={"class": "datepicker", "autocomplete": "off"}))
    cwes = cwes_field
    vulnerability_ids = vulnerability_ids_field

    cvss_info = forms.CharField(
        label="CVSS",
        widget=BulletListDisplayWidget(CVSS_CALCULATOR_URLS),
        required=False,
        disabled=True)

    cvssv3 = forms.CharField(label="CVSS3 Vector", max_length=117, required=False, widget=forms.TextInput(attrs={"class": "cvsscalculator", "data-toggle": "dropdown", "aria-haspopup": "true", "aria-expanded": "false"}))
    cvssv3_score = forms.FloatField(label="CVSS3 Score", required=False, max_value=10.0, min_value=0.0)
    cvssv4 = forms.CharField(label="CVSS4 Vector", max_length=255, required=False)
    cvssv4_score = forms.FloatField(label="CVSS4 Score", required=False, max_value=10.0, min_value=0.0)

    description = forms.CharField(widget=forms.Textarea)
    severity = forms.ChoiceField(
        choices=SEVERITY_CHOICES,
        error_messages={
            "required": "Select valid choice: In Progress, On Hold, Completed",
            "invalid_choice": "Select valid choice: Critical,High,Medium,Low"})
    mitigation = forms.CharField(widget=forms.Textarea, required=False)
    impact = forms.CharField(widget=forms.Textarea, required=False)
    request = forms.CharField(widget=forms.Textarea, required=False)
    response = forms.CharField(widget=forms.Textarea, required=False)
    endpoints = forms.ModelMultipleChoiceField(queryset=Location.objects.none(), required=False, label="Systems / Endpoints")
    endpoints_to_add = forms.CharField(max_length=5000, required=False, label="Endpoints to add",
                               help_text="The IP address, host name or full URL. You may enter one endpoint per line. "
                                         "Each must be valid.",
                               widget=forms.widgets.Textarea(attrs={"rows": "3", "cols": "400"}))
    references = forms.CharField(widget=forms.Textarea, required=False)

    mitigated = forms.DateField(required=False, help_text="Date and time when the flaw has been fixed", widget=forms.TextInput(attrs={"class": "datepicker", "autocomplete": "off"}))
    mitigated_by = forms.ModelChoiceField(required=False, queryset=Dojo_User.objects.none())

    publish_date = forms.DateField(widget=forms.TextInput(attrs={"class": "datepicker", "autocomplete": "off"}), required=False)
    planned_remediation_date = forms.DateField(widget=forms.TextInput(attrs={"class": "datepicker", "autocomplete": "off"}), required=False)
    planned_remediation_version = forms.CharField(max_length=99, required=False)
    effort_for_fixing = forms.ChoiceField(
        required=False,
        choices=EFFORT_FOR_FIXING_CHOICES,
        error_messages={
            "invalid_choice": EFFORT_FOR_FIXING_INVALID_CHOICE})

    # the only reliable way without hacking internal fields to get predicatble ordering is to make it explicit
    field_order = ("title", "group", "date", "sla_start_date", "sla_expiration_date", "cwes", "vulnerability_ids", "severity", "cvss_info", "cvssv3",
                   "cvssv3_score", "cvssv4", "cvssv4_score", "description", "mitigation", "impact", "request", "response", "steps_to_reproduce", "severity_justification",
                   "endpoints", "endpoints_to_add", "references", "active", "mitigated", "mitigated_by", "verified", "false_p", "duplicate",
                   "out_of_scope", "risk_accept", "under_defect_review")

    def __init__(self, *args, **kwargs):
        req_resp = None
        if "req_resp" in kwargs:
            req_resp = kwargs.pop("req_resp")

        self.can_edit_mitigated_data = kwargs.pop("can_edit_mitigated_data") if "can_edit_mitigated_data" in kwargs \
            else False

        super().__init__(*args, **kwargs)

        # Pre-fill all CWEs (primary first, CWE-<n> form) on edit; mirrors the vulnerability_ids field.
        if self.instance and self.instance.pk:
            self.fields["cwes"].initial = "\n".join(self.instance.cwes)

        if settings.V3_FEATURE_LOCATIONS:
            self.fields["endpoints"].queryset = Location.objects.filter(products__product=self.instance.test.engagement.product)
            if self.instance and self.instance.pk:
                self.fields["endpoints"].initial = Location.objects.filter(findings__finding=self.instance)
        else:
            # TODO: Delete this after the move to Locations
            self.fields["endpoints"].queryset = Endpoint.objects.filter(product=self.instance.test.engagement.product)
            if self.instance and self.instance.pk:
                self.fields["endpoints"].initial = self.instance.endpoints.all()

        self.fields["mitigated_by"].queryset = get_authorized_users("edit")

        # do not show checkbox if finding is not accepted and simple risk acceptance is disabled
        # if checked, always show to allow unaccept also with full risk acceptance enabled
        # when adding from template, we don't have access to the test. quickfix for now to just hide simple risk acceptance
        if not hasattr(self.instance, "test") or (not self.instance.risk_accepted and not self.instance.test.engagement.product.enable_simple_risk_acceptance):
            del self.fields["risk_accepted"]
        elif self.instance.risk_accepted:
            self.fields["risk_accepted"].help_text = "Uncheck to unaccept the risk. Use full risk acceptance from the dropdown menu if you need advanced settings such as an expiry date."
        elif self.instance.test.engagement.product.enable_simple_risk_acceptance:
            self.fields["risk_accepted"].help_text = "Check to accept the risk. Use full risk acceptance from the dropdown menu if you need advanced settings such as an expiry date."

        # self.fields['tags'].widget.choices = t
        if req_resp:
            self.fields["request"].initial = req_resp[0]
            self.fields["response"].initial = req_resp[1]

        if self.instance.duplicate:
            self.fields["duplicate"].help_text = "Original finding that is being duplicated here (readonly). Use view finding page to manage duplicate relationships. Unchecking duplicate here will reset this findings duplicate status, but will trigger deduplication logic."
        else:
            self.fields["duplicate"].help_text = "You can mark findings as duplicate only from the view finding page."

        self.fields["sla_start_date"].disabled = True
        self.fields["sla_expiration_date"].disabled = True

        if self.can_edit_mitigated_data:
            if hasattr(self, "instance"):
                self.fields["mitigated"].initial = self.instance.mitigated
                self.fields["mitigated_by"].initial = self.instance.mitigated_by
        else:
            del self.fields["mitigated"]
            del self.fields["mitigated_by"]

        if not is_finding_groups_enabled() or not hasattr(self.instance, "test"):
            del self.fields["group"]
        else:
            self.fields["group"].queryset = self.instance.test.finding_group_set.all()
            self.fields["group"].initial = self.instance.finding_group

        self.endpoints_to_add_list = []

        # Hide CVSS fields based on system settings
        hide_cvss_fields_if_disabled(self)

    def clean(self):
        cleaned_data = super().clean()

        if (cleaned_data["active"] or cleaned_data["verified"]) and cleaned_data["duplicate"]:
            msg = "Duplicate findings cannot be verified or active"
            raise forms.ValidationError(msg)
        if cleaned_data["false_p"] and cleaned_data["verified"]:
            msg = "False positive findings cannot be verified."
            raise forms.ValidationError(msg)
        if cleaned_data["active"] and "risk_accepted" in cleaned_data and cleaned_data["risk_accepted"]:
            msg = "Active findings cannot be risk accepted."
            raise forms.ValidationError(msg)

        if settings.V3_FEATURE_LOCATIONS:
            endpoints_to_add_list, errors = validate_locations_to_add(cleaned_data["endpoints_to_add"])
        else:
            # TODO: Delete this after the move to Locations
            endpoints_to_add_list, errors = validate_endpoints_to_add(cleaned_data["endpoints_to_add"])

        self.endpoints_to_add_list = endpoints_to_add_list

        if errors:
            raise forms.ValidationError(errors)

        return cleaned_data

    def clean_tags(self):
        tag_validator(self.cleaned_data.get("tags"))
        return self.cleaned_data.get("tags")

    def _post_clean(self):
        super()._post_clean()

        if self.can_edit_mitigated_data:
            opts = self.instance._meta
            try:
                opts.get_field("mitigated").save_form_data(self.instance, self.cleaned_data.get("mitigated"))
                opts.get_field("mitigated_by").save_form_data(self.instance, self.cleaned_data.get("mitigated_by"))
            except forms.ValidationError as e:
                self._update_errors(e)

    class Meta:
        model = Finding
        exclude = ("reporter", "url", "numerical_severity", "under_review", "reviewers", "cve", "cwe", "inherited_tags",
                   "review_requested_by", "is_mitigated", "jira_creation", "jira_change", "sonarqube_issue",
                   "endpoints", "endpoint_status")


class ApplyFindingTemplateForm(forms.Form):

    title = forms.CharField(max_length=1000, required=True)

    cwe = forms.IntegerField(label="CWE", required=False)
    vulnerability_ids = vulnerability_ids_field
    cvssv3 = forms.CharField(label="CVSSv3", max_length=117, required=False, widget=forms.TextInput(attrs={"class": "btn btn-secondary dropdown-toggle", "data-toggle": "dropdown", "aria-haspopup": "true", "aria-expanded": "false"}))
    cvssv3_score = forms.FloatField(required=False, label="CVSSv3 Score")
    cvssv4 = forms.CharField(label="CVSSv4", max_length=255, required=False)
    cvssv4_score = forms.FloatField(required=False, label="CVSSv4 Score")

    severity = forms.ChoiceField(required=False, choices=SEVERITY_CHOICES, error_messages={"required": "Select valid choice: In Progress, On Hold, Completed", "invalid_choice": "Select valid choice: Critical,High,Medium,Low"})

    description = forms.CharField(widget=forms.Textarea)
    mitigation = forms.CharField(widget=forms.Textarea, required=False)
    impact = forms.CharField(widget=forms.Textarea, required=False)
    references = forms.CharField(widget=forms.Textarea, required=False)

    # Remediation planning fields
    fix_available = forms.BooleanField(required=False)
    fix_version = forms.CharField(max_length=100, required=False)
    planned_remediation_version = forms.CharField(max_length=99, required=False)
    effort_for_fixing = forms.CharField(max_length=99, required=False)

    # Technical details fields
    steps_to_reproduce = forms.CharField(widget=forms.Textarea, required=False)
    severity_justification = forms.CharField(widget=forms.Textarea, required=False)
    component_name = forms.CharField(max_length=500, required=False)
    component_version = forms.CharField(max_length=100, required=False)

    # Notes field
    notes = forms.CharField(widget=forms.Textarea, required=False, help_text="Note content to add when applying template")

    # Endpoints field
    endpoints = forms.CharField(max_length=5000, required=False,
                                help_text="Endpoint URLs (one per line)",
                                widget=forms.widgets.Textarea(attrs={"rows": "3", "cols": "400"}))

    tags = TagField(required=False, help_text="Add tags that help describe this finding template. Choose from the list or add new tags. Press Enter key to add.", initial=Finding.tags.tag_model.objects.all().order_by("name"))

    def __init__(self, template=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["tags"].autocomplete_tags = Finding.tags.tag_model.objects.all().order_by("name")
        self.template = template
        if template:
            # Populate vulnerability_ids field initial value
            self.fields["vulnerability_ids"].initial = "\n".join(template.vulnerability_ids)

            # Populate CVSS fields from template
            if hasattr(template, "cvssv3"):
                self.fields["cvssv3"].initial = template.cvssv3
            if hasattr(template, "cvssv4"):
                self.fields["cvssv4"].initial = template.cvssv4
            if hasattr(template, "cvssv3_score"):
                self.fields["cvssv3_score"].initial = template.cvssv3_score
            if hasattr(template, "cvssv4_score"):
                self.fields["cvssv4_score"].initial = template.cvssv4_score

            # Populate all other new fields from template
            for field_name in ["fix_available", "fix_version", "planned_remediation_version",
                              "effort_for_fixing", "steps_to_reproduce", "severity_justification",
                              "component_name", "component_version", "notes"]:
                if hasattr(template, field_name):
                    value = getattr(template, field_name)
                    if value is not None:
                        self.fields[field_name].initial = value

            # Populate endpoints
            if hasattr(template, "endpoints"):
                endpoints_value = template.endpoints
                if endpoints_value:
                    if isinstance(endpoints_value, list):
                        self.fields["endpoints"].initial = "\n".join(endpoints_value)
                    else:
                        self.fields["endpoints"].initial = endpoints_value

        # Hide CVSS fields based on system settings
        hide_cvss_fields_if_disabled(self)

    def clean(self):
        cleaned_data = super().clean()

        if "title" in cleaned_data:
            if len(cleaned_data["title"]) <= 0:
                msg = "The title is required."
                raise forms.ValidationError(msg)
        else:
            msg = "The title is required."
            raise forms.ValidationError(msg)

        return cleaned_data

    def clean_tags(self):
        tag_validator(self.cleaned_data.get("tags"))
        return self.cleaned_data.get("tags")

    class Meta:
        fields = ["title", "cwe", "vulnerability_ids", "cvssv3", "cvssv3_score", "cvssv4", "cvssv4_score",
                 "severity", "description", "mitigation", "impact", "references", "tags",
                 "fix_available", "fix_version", "planned_remediation_version", "effort_for_fixing",
                 "steps_to_reproduce", "severity_justification", "component_name", "component_version",
                 "notes", "endpoints"]
        order = ("title", "cwe", "vulnerability_ids", "cvssv3", "cvssv3_score", "cvssv4", "cvssv4_score",
                 "severity", "description", "impact", "steps_to_reproduce", "severity_justification",
                 "mitigation", "fix_available", "fix_version", "planned_remediation_version",
                 "effort_for_fixing", "component_name", "component_version", "references", "notes",
                 "endpoints", "tags")


class FindingTemplateForm(forms.ModelForm):
    title = forms.CharField(max_length=1000, required=True)

    cwe = forms.IntegerField(label="CWE", required=False)
    vulnerability_ids = vulnerability_ids_field
    cvssv3 = forms.CharField(label="CVSS3 Vector", max_length=117, required=False, widget=forms.TextInput(attrs={"class": "btn btn-secondary dropdown-toggle", "data-toggle": "dropdown", "aria-haspopup": "true", "aria-expanded": "false"}))
    cvssv3_score = forms.FloatField(required=False, label="CVSSv3 Score")
    cvssv4 = forms.CharField(label="CVSS4 Vector", max_length=255, required=False)
    cvssv4_score = forms.FloatField(required=False, label="CVSSv4 Score")
    severity = forms.ChoiceField(
        required=False,
        choices=SEVERITY_CHOICES,
        error_messages={
            "required": "Select valid choice: In Progress, On Hold, Completed",
            "invalid_choice": "Select valid choice: Critical,High,Medium,Low"})

    # Remediation planning fields
    fix_available = forms.BooleanField(required=False)
    fix_version = forms.CharField(max_length=100, required=False)
    planned_remediation_version = forms.CharField(max_length=99, required=False)
    effort_for_fixing = forms.CharField(max_length=99, required=False)

    # Technical details fields
    steps_to_reproduce = forms.CharField(widget=forms.Textarea, required=False)
    severity_justification = forms.CharField(widget=forms.Textarea, required=False)
    component_name = forms.CharField(max_length=500, required=False)
    component_version = forms.CharField(max_length=100, required=False)

    # Notes field
    notes = forms.CharField(widget=forms.Textarea, required=False, help_text="Note content to add when applying template")

    # Endpoints field
    endpoints = forms.CharField(max_length=5000, required=False,
                                help_text="Endpoint URLs (one per line)",
                                widget=forms.widgets.Textarea(attrs={"rows": "3", "cols": "400"}))

    field_order = ["title", "cwe", "vulnerability_ids", "severity", "cvssv3", "cvssv3_score", "cvssv4", "cvssv4_score",
                   "description", "impact", "steps_to_reproduce", "severity_justification", "mitigation",
                   "fix_available", "fix_version", "planned_remediation_version", "effort_for_fixing",
                   "component_name", "component_version", "references", "notes", "endpoints", "tags"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["tags"].autocomplete_tags = Finding.tags.tag_model.objects.all().order_by("name")

        # Hide CVSS fields based on system settings
        hide_cvss_fields_if_disabled(self)

    class Meta:
        model = Finding_Template
        order = ("title", "cwe", "vulnerability_ids", "cvssv3", "cvssv3_score", "cvssv4", "cvssv4_score", "severity", "description", "impact",
                 "steps_to_reproduce", "severity_justification", "mitigation", "fix_available", "fix_version",
                 "planned_remediation_version", "effort_for_fixing", "component_name", "component_version",
                 "references", "notes", "endpoints", "tags")
        exclude = ("numerical_severity", "is_mitigated", "last_used", "endpoint_status", "cve", "vulnerability_ids_text")

    def clean_cvssv3(self):
        value = self.cleaned_data.get("cvssv3")
        if value:
            try:
                cvss3_validator(value)
            except ValidationError as e:
                raise forms.ValidationError(e.messages)
        return value

    def clean_cvssv4(self):
        value = self.cleaned_data.get("cvssv4")
        if value:
            try:
                cvss4_validator(value)
            except ValidationError as e:
                raise forms.ValidationError(e.messages)
        return value

    def clean_tags(self):
        tag_validator(self.cleaned_data.get("tags"))
        return self.cleaned_data.get("tags")


class DeleteFindingTemplateForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Finding_Template
        fields = ["id"]


class FindingBulkUpdateForm(forms.ModelForm):
    status = forms.BooleanField(required=False)
    risk_acceptance = forms.BooleanField(required=False)
    risk_accept = forms.BooleanField(required=False)
    risk_unaccept = forms.BooleanField(required=False)

    date = forms.DateField(required=False, widget=forms.DateInput(attrs={"class": "datepicker"}))
    planned_remediation_date = forms.DateField(required=False, widget=forms.DateInput(attrs={"class": "datepicker"}))
    planned_remediation_version = forms.CharField(required=False, max_length=99, widget=forms.TextInput(attrs={"class": "form-control"}))
    finding_group = forms.BooleanField(required=False)
    finding_group_create = forms.BooleanField(required=False)
    finding_group_create_name = forms.CharField(required=False)
    finding_group_add = forms.BooleanField(required=False)
    add_to_finding_group_id = forms.CharField(required=False)
    finding_group_remove = forms.BooleanField(required=False)
    finding_group_by = forms.BooleanField(required=False)
    finding_group_by_option = forms.CharField(required=False)

    push_to_jira = forms.BooleanField(required=False)
    # unlink_from_jira = forms.BooleanField(required=False)
    push_to_github = forms.BooleanField(required=False)
    tags = TagField(required=False, autocomplete_tags=Finding.tags.tag_model.objects.all().order_by("name"))
    notes = forms.CharField(required=False, max_length=1024, widget=forms.TextInput(attrs={"class": "form-control"}))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["severity"].required = False
        # we need to defer initialization to prevent multiple initializations if other forms are shown
        self.fields["tags"].widget.tag_options = tagulous.models.options.TagOptions(autocomplete_settings={"width": "200px", "defer": True})
        if disclaimer := get_system_setting("disclaimer_notes"):
            self.disclaimer = disclaimer.strip()

    def clean(self):
        cleaned_data = super().clean()

        if (cleaned_data["active"] or cleaned_data["verified"]) and cleaned_data["duplicate"]:
            msg = "Duplicate findings cannot be verified or active"
            raise forms.ValidationError(msg)
        if cleaned_data["false_p"] and cleaned_data["verified"]:
            msg = "False positive findings cannot be verified."
            raise forms.ValidationError(msg)
        if cleaned_data["active"] and cleaned_data.get("risk_acceptance") and cleaned_data.get("risk_accept"):
            msg = "Active findings cannot be risk accepted."
            raise forms.ValidationError(msg)
        return cleaned_data

    def clean_tags(self):
        tag_validator(self.cleaned_data.get("tags"))
        return self.cleaned_data.get("tags")

    class Meta:
        model = Finding
        fields = ("severity", "date", "planned_remediation_date", "active", "verified", "false_p", "duplicate", "out_of_scope",
                  "under_review", "is_mitigated")


class CloseFindingForm(forms.ModelForm):
    entry = forms.CharField(
        required=True, max_length=2400,
        widget=forms.Textarea, label="Notes:",
        error_messages={"required": ("The reason for closing a finding is "
                                     "required, please use the text area "
                                     "below to provide documentation.")})

    mitigated = forms.DateField(required=False, help_text="Date and time when the flaw has been fixed", widget=forms.TextInput(attrs={"class": "datepicker", "autocomplete": "off"}))
    mitigated_by = forms.ModelChoiceField(required=False, queryset=Dojo_User.objects.none())
    false_p = forms.BooleanField(initial=False, required=False, label="False Positive")
    out_of_scope = forms.BooleanField(initial=False, required=False, label="Out of Scope")
    duplicate = forms.BooleanField(initial=False, required=False, label="Duplicate")

    def __init__(self, *args, **kwargs):
        queryset = kwargs.pop("missing_note_types")
        # must pop custom kwargs before calling parent __init__ to avoid unexpected kwarg errors
        self.can_edit_mitigated_data = kwargs.pop("can_edit_mitigated_data") if "can_edit_mitigated_data" in kwargs \
            else False
        super().__init__(*args, **kwargs)
        if len(queryset) == 0:
            self.fields["note_type"].widget = forms.HiddenInput()
        else:
            self.fields["note_type"] = forms.ModelChoiceField(queryset=queryset, label="Note Type", required=True)

        if self.can_edit_mitigated_data:
            self.fields["mitigated_by"].queryset = get_authorized_users("edit")
            self.fields["mitigated"].initial = self.instance.mitigated
            self.fields["mitigated_by"].initial = self.instance.mitigated_by
        if disclaimer := get_system_setting("disclaimer_notes"):
            self.disclaimer = disclaimer.strip()

    def _post_clean(self):
        super()._post_clean()

        if self.can_edit_mitigated_data:
            opts = self.instance._meta
            if not self.cleaned_data.get("active"):
                try:
                    opts.get_field("mitigated").save_form_data(self.instance, self.cleaned_data.get("mitigated"))
                    opts.get_field("mitigated_by").save_form_data(self.instance, self.cleaned_data.get("mitigated_by"))
                except forms.ValidationError as e:
                    self._update_errors(e)

    class Meta:
        model = Notes
        fields = ["note_type", "entry", "mitigated", "mitigated_by", "false_p", "out_of_scope", "duplicate"]


class EditPlannedRemediationDateFindingForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        finding = None
        if "finding" in kwargs:
            finding = kwargs.pop("finding")

        super().__init__(*args, **kwargs)

        self.fields["planned_remediation_date"].required = True
        self.fields["planned_remediation_date"].widget = forms.DateInput(attrs={"class": "datepicker"})

        if finding is not None:
            self.fields["planned_remediation_date"].initial = finding.planned_remediation_date

    class Meta:
        model = Finding
        fields = ["planned_remediation_date"]


class DefectFindingForm(forms.ModelForm):
    CLOSE_CHOICES = (("Close Finding", "Close Finding"), ("Not Fixed", "Not Fixed"))
    defect_choice = forms.ChoiceField(required=True, choices=CLOSE_CHOICES)

    entry = forms.CharField(
        required=True, max_length=2400,
        widget=forms.Textarea, label="Notes:",
        error_messages={"required": ("The reason for closing a finding is "
                                     "required, please use the text area "
                                     "below to provide documentation.")})

    class Meta:
        model = Notes
        fields = ["entry"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if disclaimer := get_system_setting("disclaimer_notes"):
            self.disclaimer = disclaimer.strip()


class ClearFindingReviewForm(forms.ModelForm):
    entry = forms.CharField(
        required=True, max_length=2400,
        help_text="Please provide a message.",
        widget=forms.Textarea, label="Notes:",
        error_messages={"required": ("The reason for clearing a review is "
                                     "required, please use the text area "
                                     "below to provide documentation.")})

    class Meta:
        model = Finding
        fields = ["active", "verified", "false_p", "out_of_scope", "duplicate", "is_mitigated"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if disclaimer := get_system_setting("disclaimer_notes"):
            self.disclaimer = disclaimer.strip()


class ReviewFindingForm(forms.Form):
    reviewers = forms.MultipleChoiceField(
        help_text=(
            "Select all users who can review Finding. Only users with "
            "at least write permission to this finding can be selected"),
        required=False,
    )
    entry = forms.CharField(
        required=True, max_length=2400,
        help_text="Please provide a message for reviewers.",
        widget=forms.Textarea, label="Notes:",
        error_messages={"required": ("The reason for requesting a review is "
                                     "required, please use the text area "
                                     "below to provide documentation.")})
    allow_all_reviewers = forms.BooleanField(
        required=False,
        label="Allow All Eligible Reviewers",
        help_text=("Checking this box will allow any user in the drop down "
                   "above to provide a review for this finding"))

    def __init__(self, *args, **kwargs):
        finding = kwargs.pop("finding", None)
        kwargs.pop("user", None)
        super().__init__(*args, **kwargs)
        # Get the list of users
        if finding is not None:
            users = get_authorized_users_for_product_and_product_type(None, finding.test.engagement.product, "edit")
        else:
            users = get_authorized_users("edit").filter(is_active=True)
        # Save a copy of the original query to be used in the validator
        self.reviewer_queryset = users
        # Set the users in the form
        self.fields["reviewers"].choices = self._get_choices(self.reviewer_queryset)
        if disclaimer := get_system_setting("disclaimer_notes"):
            self.disclaimer = disclaimer.strip()

    @staticmethod
    def _get_choices(queryset):
        return [(item.pk, item.get_full_name()) for item in queryset]

    def clean(self):
        cleaned_data = super().clean()
        if cleaned_data.get("allow_all_reviewers", False):
            cleaned_data["reviewers"] = [user.id for user in self.reviewer_queryset]
        if len(cleaned_data.get("reviewers", [])) == 0:
            msg = "Please select at least one user from the reviewers list"
            raise ValidationError(msg)
        return cleaned_data

    class Meta:
        fields = ["reviewers", "entry", "allow_all_reviewers"]


class DeleteFindingForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Finding
        fields = ["id"]


class CopyFindingForm(forms.Form):
    test = forms.ModelChoiceField(
        required=True,
        queryset=Test.objects.none(),
        error_messages={"required": "*"})

    def __init__(self, *args, **kwargs):
        authorized_lists = kwargs.pop("tests", None)
        super().__init__(*args, **kwargs)
        self.fields["test"].queryset = authorized_lists


class FindingFormID(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Finding
        fields = ("id",)
