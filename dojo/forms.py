import logging
import re
from datetime import date, datetime
from pathlib import Path

from crum import get_current_user
from dateutil.relativedelta import relativedelta
from django import forms
from django.conf import settings
from django.contrib.auth.models import Permission
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.forms import modelformset_factory
from django.forms.widgets import Select, Widget
from django.utils import timezone
from django.utils.dates import MONTHS
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _
from tagulous.forms import TagField

from dojo.endpoint.utils import validate_endpoints_to_add
from dojo.finding.queries import get_authorized_findings
from dojo.github.ui.forms import (  # noqa: F401 -- backward compat
    DeleteGITHUBConfForm,
    ExpressGITHUBForm,
    GITHUB_IssueForm,
    GITHUB_Product_Form,
    GITHUBFindingForm,
    GITHUBForm,
)
from dojo.jira.forms import (  # noqa: F401 backward compat
    JIRA_TEMPLATE_CHOICES,
    AdvancedJIRAForm,
    BaseJiraForm,
    DeleteJIRAInstanceForm,
    JIRA_IssueForm,
    JIRAEngagementForm,
    JIRAFindingForm,
    JIRAForm,
    JIRAImportScanForm,
    JIRAProjectForm,
    get_jira_issue_template_dir_choices,
)
from dojo.labels import get_labels
from dojo.location.models import Location
from dojo.location.utils import validate_locations_to_add
from dojo.models import (
    SEVERITY_CHOICES,
    Announcement,
    App_Analysis,
    Check_List,
    Development_Environment,
    Dojo_User,
    DojoMeta,
    Endpoint,
    FileUpload,
    Finding,
    Finding_Group,
    Note_Type,
    Notes,
    Objects_Product,
    Product_API_Scan_Configuration,
    Product_Type,
    Regulation,
    Risk_Acceptance,
    SLA_Configuration,
    Test_Type,
    User,
)
from dojo.product_type.queries import get_authorized_product_types
from dojo.tools.factory import get_choices_sorted, requires_file, requires_tool_type
from dojo.user.utils import get_configuration_permissions_fields
from dojo.utils import (
    get_password_requirements_string,
    get_system_setting,
    is_finding_groups_enabled,
    is_scan_file_too_large,
)
from dojo.validators import ImporterFileExtensionValidator, tag_validator

logger = logging.getLogger(__name__)

labels = get_labels()

RE_DATE = re.compile(r"(\d{4})-(\d\d?)-(\d\d?)$")

FINDING_STATUS = (("verified", "Verified"),
                  ("false_p", "False Positive"),
                  ("duplicate", "Duplicate"),
                  ("out_of_scope", "Out of Scope"))


class MonthYearWidget(Widget):

    """
    A Widget that splits date input into two <select> boxes for month and year,
    with 'day' defaulting to the first of the month.

    Based on SelectDateWidget, in

    django/trunk/django/forms/extras/widgets.py
    """

    none_value = (0, "---")
    month_field = "%s_month"
    year_field = "%s_year"

    def __init__(self, attrs=None, years=None, *, required=True):
        # years is an optional list/tuple of years to use in the
        # "year" select box.
        self.attrs = attrs or {}
        self.required = required
        if years:
            self.years = years
        else:
            this_year = date.today().year
            self.years = list(range(this_year - 10, this_year + 1))

    def render(self, name, value, attrs=None, renderer=None):
        try:
            year_val, month_val = value.year, value.month
        except AttributeError:
            year_val = month_val = None
            if isinstance(value, str):
                match = RE_DATE.match(value)
                if match:
                    year_val, month_val = match[1], match[2]

        output = []

        id_ = self.attrs.get("id", f"id_{name}")

        month_choices = list(MONTHS.items())
        if not (self.required and value):
            month_choices.append(self.none_value)
        month_choices.sort()
        local_attrs = self.build_attrs({"id": self.month_field % id_})
        s = Select(choices=month_choices)
        select_html = s.render(self.month_field % name, month_val, local_attrs)

        output.append(select_html)

        year_choices = [(i, i) for i in self.years]
        if not (self.required and value):
            year_choices.insert(0, self.none_value)
        local_attrs["id"] = self.year_field % id_
        s = Select(choices=year_choices)
        select_html = s.render(self.year_field % name, year_val, local_attrs)
        output.append(select_html)

        return mark_safe("\n".join(output))

    @classmethod
    def id_for_label(cls, id_):
        return f"{id_}_month"

    def value_from_datadict(self, data, files, name):
        y = data.get(self.year_field % name)
        m = data.get(self.month_field % name)
        if y == m == "0":
            return None
        if y and m:
            return f"{y}-{m}-{1}"
        return data.get(name, None)


from dojo.product_type.ui.forms import Add_Product_Type_AuthorizedUsersForm, Delete_Product_TypeForm, Product_TypeForm  # noqa: E402, F401, I001


class Test_TypeForm(forms.ModelForm):
    class Meta:
        model = Test_Type
        exclude = ["dynamically_generated"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if self.instance.pk:
            self.fields["name"].widget.attrs["readonly"] = True

    def clean_name(self):
        if self.instance.pk:
            return self.instance.name
        return self.cleaned_data["name"]


class Development_EnvironmentForm(forms.ModelForm):
    class Meta:
        model = Development_Environment
        fields = ["name"]


class Delete_Dev_EnvironmentForm(forms.ModelForm):
    class Meta:
        model = Development_Environment
        fields = ["id"]


# Re-exported for external consumers (finding_group/test/engagement/product views + unittests).
# The remaining finding forms live only in dojo.finding.ui.forms and are imported there by finding's own views.
from dojo.finding.ui.forms import (  # noqa: E402, F401 -- backward compat
    AddFindingForm,
    AddFindingsRiskAcceptanceForm,
    AdHocFindingForm,
    DeleteFindingGroupForm,
    EditFindingGroupForm,
    FindingBulkUpdateForm,
)


class Authorize_User_For_ProductTypesForm(forms.Form):
    product_types = forms.ModelMultipleChoiceField(
        queryset=Product_Type.objects.none(), required=True, label=labels.ORG_PLURAL_LABEL,
    )

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        self.fields["product_types"].queryset = (
            Product_Type.objects.exclude(authorized_users=user).order_by("name")
        )


class NoteTypeForm(forms.ModelForm):
    description = forms.CharField(widget=forms.Textarea(attrs={}),
                                  required=True)

    class Meta:
        model = Note_Type
        fields = ["name", "description", "is_single", "is_mandatory"]


class EditNoteTypeForm(NoteTypeForm):

    def __init__(self, *args, **kwargs):
        is_single = kwargs.pop("is_single")
        super().__init__(*args, **kwargs)
        if is_single is False:
            self.fields["is_single"].widget = forms.HiddenInput()


class DisableOrEnableNoteTypeForm(NoteTypeForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["name"].disabled = True
        self.fields["description"].disabled = True
        self.fields["is_single"].disabled = True
        self.fields["is_mandatory"].disabled = True
        self.fields["is_active"].disabled = True

    class Meta:
        model = Note_Type
        fields = "__all__"


class DojoMetaDataForm(forms.ModelForm):
    def full_clean(self):
        # inject all fk_map values
        for field, value in self.fk_map.items():
            setattr(self.instance, field, value)
        super().full_clean()
        try:
            self.instance.validate_unique()
        except ValidationError:
            msg = "A metadata entry with the same name exists already for this object."
            self.add_error("name", msg)

    def __init__(self, *args, **kwargs):
        self.fk_map = kwargs.pop("fk_map", {})
        super().__init__(*args, **kwargs)

    class Meta:
        model = DojoMeta
        fields = "__all__"


DojoMetaFormSet = modelformset_factory(
    DojoMeta,
    form=DojoMetaDataForm,
    extra=1,
    can_delete=True,
)


class ImportScanForm(forms.Form):
    active_verified_choices = [("not_specified", "Not specified (default)"),
                               ("force_to_true", "Force to True"),
                               ("force_to_false", "Force to False")]
    test_title = forms.CharField(max_length=255, required=False, label="Test Title",
                                 help_text="Optional title for the Test to be created. If empty, the scan type is used.")
    scan_date = forms.DateTimeField(
        required=False,
        label="Scan Completion Date",
        help_text="Scan completion date will be used on all findings.",
        widget=forms.TextInput(attrs={"class": "datepicker"}))
    minimum_severity = forms.ChoiceField(help_text="Minimum severity level to be imported",
                                         required=True,
                                         choices=SEVERITY_CHOICES)
    active = forms.ChoiceField(required=True, choices=active_verified_choices,
                               help_text="Force findings to be active/inactive, or default to the original tool")
    verified = forms.ChoiceField(required=True, choices=active_verified_choices,
                               help_text="Force findings to be verified/not verified, or default to the original tool")

    # help_do_not_reactivate = 'Select if the import should ignore active findings from the report, useful for triage-less scanners. Will keep existing findings closed, without reactivating them. For more information check the docs.'
    # do_not_reactivate = forms.BooleanField(help_text=help_do_not_reactivate, required=False)
    scan_type = forms.ChoiceField(required=True, choices=get_choices_sorted)
    environment = forms.ModelChoiceField(
        queryset=Development_Environment.objects.all().order_by("name"))
    endpoints = forms.ModelMultipleChoiceField(Location.objects, required=False, label="Systems / Endpoints")
    endpoints_to_add = forms.CharField(max_length=5000, required=False, label="Endpoints to add",
                                       help_text="The IP address, host name or full URL. You may enter one endpoint per line. "
                                                 "Each must be valid.",
                                       widget=forms.widgets.Textarea(attrs={"rows": "3", "cols": "400"}))
    version = forms.CharField(max_length=100, required=False, help_text="Version that was scanned.")
    branch_tag = forms.CharField(max_length=100, required=False, help_text="Branch or Tag that was scanned.")
    commit_hash = forms.CharField(max_length=100, required=False, help_text="Commit that was scanned.")
    build_id = forms.CharField(max_length=100, required=False, help_text="ID of the build that was scanned.")
    api_scan_configuration = forms.ModelChoiceField(Product_API_Scan_Configuration.objects, required=False, label="API Scan Configuration")
    service = forms.CharField(max_length=200, required=False,
        help_text="A service is a self-contained piece of functionality within a Product. "
                  "This is an optional field which is used in deduplication and closing of old findings when set.")
    source_code_management_uri = forms.URLField(max_length=600, required=False, help_text="Resource link to source code")
    tags = TagField(required=False, help_text="Add tags that help describe this scan.  "
                    "Choose from the list or add new tags. Press Enter key to add.")
    file = forms.FileField(
        widget=forms.widgets.FileInput(attrs={"accept": ", ".join(settings.FILE_IMPORT_TYPES)}),
        label="Choose report file",
        allow_empty_file=True,
        required=False,
        validators=[ImporterFileExtensionValidator()],
    )

    # Close Old Findings has changed. The default is engagement only, and it requires a second flag to expand to the product scope.
    # Exposing the choice as two different check boxes.
    # If 'close_old_findings_product_scope' is selected, the backend will ensure that both flags are set.
    close_old_findings = forms.BooleanField(help_text="Old findings no longer present in the new report get closed as mitigated when importing. "
                                                        "If service has been set, only the findings for this service will be closed; "
                                                        "if no service is set, only findings without a service will be closed. "
                                                        "This affects findings within the same engagement by default.",
                                            label="Close old findings",
                                            required=False,
                                            initial=False)
    close_old_findings_product_scope = forms.BooleanField(help_text=labels.ASSET_FINDINGS_CLOSE_HELP,
                                            label=labels.ASSET_FINDINGS_CLOSE_LABEL,
                                            required=False,
                                            initial=False)
    apply_tags_to_findings = forms.BooleanField(
        help_text="If set to True, the tags will be applied to the findings",
        label="Apply Tags to Findings",
        required=False,
        initial=False,
    )
    apply_tags_to_endpoints = forms.BooleanField(
        help_text="If set to True, the tags will be applied to the endpoints",
        label="Apply Tags to Endpoints",
        required=False,
        initial=False,
    )

    if is_finding_groups_enabled():
        group_by = forms.ChoiceField(required=False, choices=Finding_Group.GROUP_BY_OPTIONS, help_text="Choose an option to automatically group new findings by the chosen option.")
        create_finding_groups_for_all_findings = forms.BooleanField(help_text="If unchecked, finding groups will only be created when there is more than one grouped finding", required=False, initial=True)

    def __init__(self, *args, **kwargs):
        environment = kwargs.pop("environment", None)
        endpoints = kwargs.pop("endpoints", None)
        api_scan_configuration = kwargs.pop("api_scan_configuration", None)
        super().__init__(*args, **kwargs)
        self.fields["active"].initial = self.active_verified_choices[0]
        self.fields["verified"].initial = self.active_verified_choices[0]
        if environment:
            self.fields["environment"].initial = environment
        if endpoints:
            self.fields["endpoints"].queryset = endpoints
        elif not settings.V3_FEATURE_LOCATIONS:
            # TODO: Delete this after the move to Locations
            self.fields["endpoints"].queryset = Endpoint.objects
        if api_scan_configuration:
            self.fields["api_scan_configuration"].queryset = api_scan_configuration
        # couldn't find a cleaner way to add empty default
        if "group_by" in self.fields:
            choices = self.fields["group_by"].choices
            choices.insert(0, ("", "---------"))
            self.fields["group_by"].choices = choices

        self.endpoints_to_add_list = []

    def clean(self):
        cleaned_data = super().clean()
        scan_type = cleaned_data.get("scan_type")
        file = cleaned_data.get("file")
        tool_type = requires_tool_type(scan_type)
        if requires_file(scan_type) and not file:
            msg = _("Uploading a Report File is required for %s") % scan_type
            raise forms.ValidationError(msg)
        if file and is_scan_file_too_large(file):
            msg = _("Report file is too large. Maximum supported size is %d MB") % settings.SCAN_FILE_MAX_SIZE
            raise forms.ValidationError(msg)
        if tool_type:
            api_scan_configuration = cleaned_data.get("api_scan_configuration")
            if api_scan_configuration and tool_type != api_scan_configuration.tool_configuration.tool_type.name:
                msg = f"API scan configuration must be of tool type {tool_type}"
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

    # date can only be today or in the past, not the future
    def clean_scan_date(self):
        date = self.cleaned_data.get("scan_date", None)
        if date and date.date() > datetime.today().date():
            msg = "The date cannot be in the future!"
            raise forms.ValidationError(msg)
        return date

    def get_scan_type(self):
        return self.cleaned_data["scan_type"]


class ReImportScanForm(forms.Form):
    active_verified_choices = [("not_specified", "Not specified (default)"),
                               ("force_to_true", "Force to True"),
                               ("force_to_false", "Force to False")]
    scan_date = forms.DateTimeField(
        required=False,
        label="Scan Completion Date",
        help_text="Scan completion date will be used on all findings.",
        widget=forms.TextInput(attrs={"class": "datepicker"}))
    minimum_severity = forms.ChoiceField(help_text="Minimum severity level to be imported",
                                         required=True,
                                         choices=SEVERITY_CHOICES[0:4])
    active = forms.ChoiceField(required=True, choices=active_verified_choices,
                               help_text="Force findings to be active/inactive, or default to the original tool")
    verified = forms.ChoiceField(required=True, choices=active_verified_choices,
                             help_text="Force findings to be verified/not verified, or default to the original tool")

    help_do_not_reactivate = "Select if the import should ignore active findings from the report, useful for triage-less scanners. Will keep existing findings closed, without reactivating them. For more information check the docs."
    do_not_reactivate = forms.BooleanField(help_text=help_do_not_reactivate, required=False)
    endpoints = forms.ModelMultipleChoiceField(Location.objects, required=False, label="Systems / Endpoints")
    tags = TagField(required=False, help_text="Modify existing tags that help describe this scan.  "
                    "Choose from the list or add new tags. Press Enter key to add.")
    file = forms.FileField(
        widget=forms.widgets.FileInput(attrs={"accept": ", ".join(settings.FILE_IMPORT_TYPES)}),
        label="Choose report file",
        allow_empty_file=True,
        required=False,
        validators=[ImporterFileExtensionValidator()],
    )
    close_old_findings = forms.BooleanField(help_text="Select if old findings in the same test that are no longer present in the report get closed as mitigated when importing.",
                                            required=False, initial=True)
    version = forms.CharField(max_length=100, required=False, help_text="Version that will be set on existing Test object. Leave empty to leave existing value in place.")
    branch_tag = forms.CharField(max_length=100, required=False, help_text="Branch or Tag that was scanned.")
    commit_hash = forms.CharField(max_length=100, required=False, help_text="Commit that was scanned.")
    build_id = forms.CharField(max_length=100, required=False, help_text="ID of the build that was scanned.")
    api_scan_configuration = forms.ModelChoiceField(Product_API_Scan_Configuration.objects, required=False, label="API Scan Configuration")
    service = forms.CharField(max_length=200, required=False, help_text="A service is a self-contained piece of functionality within a Product. This is an optional field which is used in deduplication of findings when set.")
    source_code_management_uri = forms.URLField(max_length=600, required=False, help_text="Resource link to source code")
    apply_tags_to_findings = forms.BooleanField(
        help_text="If set to True, the tags will be applied to the findings",
        label="Apply Tags to Findings",
        required=False,
        initial=False,
    )
    apply_tags_to_endpoints = forms.BooleanField(
        help_text="If set to True, the tags will be applied to the endpoints",
        label="Apply Tags to Endpoints",
        required=False,
        initial=False,
    )

    if is_finding_groups_enabled():
        group_by = forms.ChoiceField(required=False, choices=Finding_Group.GROUP_BY_OPTIONS, help_text="Choose an option to automatically group new findings by the chosen option")
        create_finding_groups_for_all_findings = forms.BooleanField(help_text="If unchecked, finding groups will only be created when there is more than one grouped finding", required=False, initial=True)

    def __init__(self, *args, test=None, **kwargs):
        endpoints = kwargs.pop("endpoints", None)
        api_scan_configuration = kwargs.pop("api_scan_configuration", None)
        api_scan_configuration_queryset = kwargs.pop("api_scan_configuration_queryset", None)
        super().__init__(*args, **kwargs)
        self.fields["active"].initial = self.active_verified_choices[0]
        self.fields["verified"].initial = self.active_verified_choices[0]
        self.scan_type = None
        if test:
            self.scan_type = test.test_type.name
            self.fields["tags"].initial = test.tags.all()
        if endpoints:
            self.fields["endpoints"].queryset = endpoints
        elif not settings.V3_FEATURE_LOCATIONS:
            # TODO: Delete this after the move to Locations
            self.fields["endpoints"].queryset = Endpoint.objects
        if api_scan_configuration:
            self.initial["api_scan_configuration"] = api_scan_configuration
        if api_scan_configuration_queryset:
            self.fields["api_scan_configuration"].queryset = api_scan_configuration_queryset
        # couldn't find a cleaner way to add empty default
        if "group_by" in self.fields:
            choices = self.fields["group_by"].choices
            choices.insert(0, ("", "---------"))
            self.fields["group_by"].choices = choices

    def clean(self):
        cleaned_data = super().clean()
        file = cleaned_data.get("file")
        if requires_file(self.scan_type) and not file:
            msg = _("Uploading a report file is required for re-uploading findings.")
            raise forms.ValidationError(msg)
        if file and is_scan_file_too_large(file):
            msg = _("Report file is too large. Maximum supported size is %d MB") % settings.SCAN_FILE_MAX_SIZE
            raise forms.ValidationError(msg)
        tool_type = requires_tool_type(self.scan_type)
        if tool_type:
            api_scan_configuration = cleaned_data.get("api_scan_configuration")
            if api_scan_configuration and tool_type != api_scan_configuration.tool_configuration.tool_type.name:
                msg = f"API scan configuration must be of tool type {tool_type}"
                raise forms.ValidationError(msg)

        return cleaned_data

    def clean_tags(self):
        tag_validator(self.cleaned_data.get("tags"))
        return self.cleaned_data.get("tags")

    # date can only be today or in the past, not the future
    def clean_scan_date(self):
        date = self.cleaned_data.get("scan_date", None)
        if date and date.date() > timezone.localtime(timezone.now()).date():
            msg = "The date cannot be in the future!"
            raise forms.ValidationError(msg)
        return date


from dojo.endpoint.ui.forms import (  # noqa: E402, F401 -- backward compat re-export
    AddEndpointForm,
    DeleteEndpointForm,
    EditEndpointForm,
    ImportEndpointMetaForm,
)


class DoneForm(forms.Form):
    done = forms.BooleanField()


class UploadThreatForm(forms.Form):
    file = forms.FileField(widget=forms.widgets.FileInput(
        attrs={"accept": ".jpg,.png,.pdf"}),
        label="Select Threat Model")

    def clean(self):
        if (file := self.cleaned_data.get("file", None)) is not None:
            path = Path(file.name)
            ext = path.suffix
            valid_extensions = [".jpg", ".png", ".pdf"]
            if ext.lower() not in valid_extensions:
                if accepted_extensions := f"{', '.join(valid_extensions)}":
                    msg = (
                        "Unsupported extension. Supported extensions are as "
                        f"follows: {accepted_extensions}"
                    )
                else:
                    msg = (
                        "File uploads are prohibited due to the list of acceptable "
                        "file extensions being empty"
                    )
                raise ValidationError(msg)


class EditRiskAcceptanceForm(forms.ModelForm):
    # unfortunately django forces us to repeat many things here. choices, default, required etc.
    recommendation = forms.ChoiceField(choices=Risk_Acceptance.TREATMENT_CHOICES, initial=Risk_Acceptance.TREATMENT_ACCEPT, widget=forms.RadioSelect, label="Security Recommendation")
    decision = forms.ChoiceField(choices=Risk_Acceptance.TREATMENT_CHOICES, initial=Risk_Acceptance.TREATMENT_ACCEPT, widget=forms.RadioSelect)

    path = forms.FileField(label="Proof", required=False, widget=forms.widgets.FileInput(attrs={"accept": ", ".join(settings.FILE_IMPORT_TYPES)}))
    expiration_date = forms.DateTimeField(required=False, widget=forms.TextInput(attrs={"class": "datepicker"}))

    class Meta:
        model = Risk_Acceptance
        exclude = ["accepted_findings", "notes"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["path"].help_text = f"Existing proof uploaded: {self.instance.filename()}" if self.instance.filename() else "None"
        self.fields["expiration_date_warned"].disabled = True
        self.fields["expiration_date_handled"].disabled = True

    def clean_path(self):
        if (data := self.cleaned_data.get("path")) is not None:
            ext = Path(data.name).suffix  # [0] returns path+filename
            valid_extensions = settings.FILE_UPLOAD_TYPES
            if ext.lower() not in valid_extensions:
                if accepted_extensions := f"{', '.join(valid_extensions)}":
                    msg = f"Unsupported extension. Supported extensions are as follows: {accepted_extensions}"
                else:
                    msg = "File uploads are prohibited due to the list of acceptable file extensions being empty"
                raise ValidationError(msg)
        return data


class RiskAcceptanceForm(EditRiskAcceptanceForm):
    accepted_findings = forms.ModelMultipleChoiceField(
        queryset=Finding.objects.none(), required=True,
        widget=forms.widgets.SelectMultiple(attrs={"size": 10}),
        help_text=("Active, verified findings listed, please select to add findings."))
    notes = forms.CharField(required=False, max_length=2400,
                            widget=forms.Textarea,
                            label="Notes")

    class Meta:
        model = Risk_Acceptance
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        expiration_delta_days = get_system_setting("risk_acceptance_form_default_days")
        logger.debug("expiration_delta_days: %i", expiration_delta_days)
        if expiration_delta_days > 0:
            expiration_date = timezone.now().date() + relativedelta(days=expiration_delta_days)
            # logger.debug('setting default expiration_date: %s', expiration_date)
            self.fields["expiration_date"].initial = expiration_date
        # self.fields['path'].help_text = 'Existing proof uploaded: %s' % self.instance.filename() if self.instance.filename() else 'None'
        self.fields["accepted_findings"].queryset = get_authorized_findings("edit")
        if disclaimer := get_system_setting("disclaimer_notes"):
            self.disclaimer = disclaimer.strip()


class BaseManageFileFormSet(forms.BaseModelFormSet):
    def clean(self):
        """Validate the IP/Mask combo is in CIDR format"""
        if any(self.errors):
            # Don't bother validating the formset unless each form is valid on its own
            return
        for form in self.forms:
            file = form.cleaned_data.get("file", None)
            if file:
                path = Path(file.name)
                ext = path.suffix
                valid_extensions = settings.FILE_UPLOAD_TYPES
                if ext.lower() not in valid_extensions:
                    if accepted_extensions := f"{', '.join(valid_extensions)}":
                        msg = (
                            "Unsupported extension. Supported extensions are as "
                            f"follows: {accepted_extensions}"
                        )
                    else:
                        msg = (
                            "File uploads are prohibited due to the list of acceptable "
                            "file extensions being empty"
                        )
                    form.add_error("file", msg)


ManageFileFormSet = modelformset_factory(FileUpload, extra=3, max_num=10, fields=["title", "file"], can_delete=True, formset=BaseManageFileFormSet)


class ReplaceRiskAcceptanceProofForm(forms.ModelForm):
    path = forms.FileField(label="Proof", required=True, widget=forms.widgets.FileInput(attrs={"accept": ".jpg,.png,.pdf"}))

    class Meta:
        model = Risk_Acceptance
        fields = ["path"]


class CheckForm(forms.ModelForm):
    options = (("Pass", "Pass"), ("Fail", "Fail"), ("N/A", "N/A"))
    session_management = forms.ChoiceField(choices=options)
    encryption_crypto = forms.ChoiceField(choices=options)
    configuration_management = forms.ChoiceField(choices=options)
    authentication = forms.ChoiceField(choices=options)
    authorization_and_access_control = forms.ChoiceField(choices=options)
    data_input_sanitization_validation = forms.ChoiceField(choices=options)
    sensitive_data = forms.ChoiceField(choices=options)
    other = forms.ChoiceField(choices=options)

    def __init__(self, *args, **kwargs):
        findings = kwargs.pop("findings")
        super().__init__(*args, **kwargs)
        self.fields["session_issues"].queryset = findings
        self.fields["crypto_issues"].queryset = findings
        self.fields["config_issues"].queryset = findings
        self.fields["auth_issues"].queryset = findings
        self.fields["author_issues"].queryset = findings
        self.fields["data_issues"].queryset = findings
        self.fields["sensitive_issues"].queryset = findings
        self.fields["other_issues"].queryset = findings

    class Meta:
        model = Check_List
        fields = ["session_management", "session_issues", "encryption_crypto", "crypto_issues",
                  "configuration_management", "config_issues", "authentication", "auth_issues",
                  "authorization_and_access_control", "author_issues",
                  "data_input_sanitization_validation", "data_issues",
                  "sensitive_data", "sensitive_issues", "other", "other_issues"]


# Engagement forms live in dojo/engagement/ui/forms.py. Re-exported here for
# backward compat. DeleteEngagementForm has no external consumers, so it is not
# re-exported (imported directly from dojo.engagement.ui.forms by its only user).
from dojo.engagement.ui.forms import (  # noqa: E402, F401 -- backward compat
    AddEngagementForm,
    DeleteEngagementPresetsForm,
    EngagementPresetsForm,
    EngForm,
    ExistingEngagementForm,
)
from dojo.test.ui.forms import TestForm  # noqa: E402, F401 -- backward compat


class NoteForm(forms.ModelForm):
    entry = forms.CharField(max_length=2400, widget=forms.Textarea(attrs={"rows": 4, "cols": 15}),
                            label="Notes:")

    class Meta:
        model = Notes
        fields = ["entry", "private"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if disclaimer := get_system_setting("disclaimer_notes"):
            self.disclaimer = disclaimer.strip()


class TypedNoteForm(NoteForm):

    def __init__(self, *args, **kwargs):
        queryset = kwargs.pop("available_note_types")
        super().__init__(*args, **kwargs)
        self.fields["note_type"] = forms.ModelChoiceField(queryset=queryset, label="Note Type", required=True)

    class Meta:
        model = Notes
        fields = ["note_type", "entry", "private"]


class DeleteNoteForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Notes
        fields = ["id"]


class WeeklyMetricsForm(forms.Form):
    dates = forms.ChoiceField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        wmf_options = []

        for i in range(6):
            # Weeks start on Monday
            curr = datetime.now() - relativedelta(weeks=i)
            start_of_period = curr - relativedelta(weeks=1, weekday=0,
                                                   hour=0, minute=0, second=0)
            end_of_period = curr + relativedelta(weeks=0, weekday=0,
                                                 hour=0, minute=0, second=0)

            wmf_options.append((end_of_period.strftime("%b %d %Y %H %M %S %Z"),
                                start_of_period.strftime("%b %d")
                                + " - " + end_of_period.strftime("%b %d")))

        wmf_options = tuple(wmf_options)

        self.fields["dates"].choices = wmf_options


class SimpleMetricsForm(forms.Form):
    date = forms.DateField(
        label="",
        widget=MonthYearWidget())


class SimpleSearchForm(forms.Form):
    query = forms.CharField(required=False)


class DateRangeMetrics(forms.Form):
    start_date = forms.DateField(required=True, label="To",
                                 widget=forms.TextInput(attrs={"class": "datepicker", "autocomplete": "off"}))
    end_date = forms.DateField(required=True,
                               label="From",
                               widget=forms.TextInput(attrs={"class": "datepicker", "autocomplete": "off"}))


class MetricsFilterForm(forms.Form):
    start_date = forms.DateField(required=False,
                                 label="To",
                                 widget=forms.TextInput(attrs={"class": "datepicker", "autocomplete": "off"}))
    end_date = forms.DateField(required=False,
                               label="From",
                               widget=forms.TextInput(attrs={"class": "datepicker", "autocomplete": "off"}))
    finding_status = forms.MultipleChoiceField(
        required=False,
        widget=forms.CheckboxSelectMultiple,
        choices=FINDING_STATUS,
        label="Status")
    severity = forms.MultipleChoiceField(required=False,
                                         choices=(("Low", "Low"),
                                                  ("Medium", "Medium"),
                                                  ("High", "High"),
                                                  ("Critical", "Critical")),
                                         help_text=('Hold down "Control", or '
                                                    '"Command" on a Mac, to '
                                                    'select more than one.'))
    exclude_product_types = forms.ModelMultipleChoiceField(
        required=False, queryset=Product_Type.objects.all().order_by("name"))

    # add the ability to exclude the exclude_product_types field
    def __init__(self, *args, **kwargs):
        exclude_product_types = kwargs.pop("exclude_product_types", False)
        super().__init__(*args, **kwargs)
        if exclude_product_types:
            del self.fields["exclude_product_types"]


class ChangePasswordForm(forms.Form):
    current_password = forms.CharField(widget=forms.PasswordInput,
        required=True)
    new_password = forms.CharField(widget=forms.PasswordInput,
        required=True,
        validators=[validate_password],
        help_text="")
    confirm_password = forms.CharField(widget=forms.PasswordInput,
        required=True,
        validators=[validate_password],
        help_text="Password must match the new password entered above.")

    def __init__(self, *args, **kwargs):
        self.user = None
        if "user" in kwargs:
            self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)
        self.fields["new_password"].help_text = get_password_requirements_string()

    def clean(self):
        cleaned_data = super().clean()

        current_password = self.cleaned_data.get("current_password")
        new_password = self.cleaned_data.get("new_password")
        confirm_password = self.cleaned_data.get("confirm_password")

        if not self.user.check_password(current_password):
            msg = "Current password is incorrect."
            raise forms.ValidationError(msg)
        if new_password == current_password:
            msg = "New password must be different from current password."
            raise forms.ValidationError(msg)
        if new_password != confirm_password:
            msg = "Passwords do not match."
            raise forms.ValidationError(msg)

        return cleaned_data


# Product forms live in dojo/product/ui/forms.py. Re-exported here for backward
# compat: ProductCountsFormBase is subclassed by ProductTypeCountsForm below,
# Authorize_User_For_ProductsForm by dojo/user/views.py, ProductTagCountsForm by
# dojo/metrics/views.py. The other product forms are imported directly from
# dojo.product.ui.forms by the product module's own views.
from dojo.product.ui.forms import (  # noqa: E402, F401 -- backward compat
    Authorize_User_For_ProductsForm,
    ProductCountsFormBase,
    ProductTagCountsForm,
)


class ProductTypeCountsForm(ProductCountsFormBase):
    product_type = forms.ModelChoiceField(required=True,
                                          queryset=Product_Type.objects.none(),
                                          label=labels.ORG_LABEL,
                                          error_messages={
                                              "required": "*"})

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["product_type"].queryset = get_authorized_product_types("view")


class APIKeyForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = User
        exclude = ["username", "first_name", "last_name", "email", "is_active",
                   "is_staff", "is_superuser", "password", "last_login", "groups",
                   "date_joined", "user_permissions"]


class ReportOptionsForm(forms.Form):
    yes_no = (("0", "No"), ("1", "Yes"))
    include_finding_notes = forms.ChoiceField(choices=yes_no, label="Finding Notes")
    include_finding_images = forms.ChoiceField(choices=yes_no, label="Finding Images")
    include_executive_summary = forms.ChoiceField(choices=yes_no, label="Executive Summary")
    include_table_of_contents = forms.ChoiceField(choices=yes_no, label="Table of Contents")
    include_disclaimer = forms.ChoiceField(choices=yes_no, label="Disclaimer")
    report_type = forms.ChoiceField(choices=(("HTML", "HTML"),))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if get_system_setting("disclaimer_reports_forced"):
            self.fields["include_disclaimer"].disabled = True
            self.fields["include_disclaimer"].initial = "1"  # represents yes
            self.fields["include_disclaimer"].help_text = "Administrator of the system enforced placement of disclaimer in all reports. You are not able exclude disclaimer from this report."


class CustomReportOptionsForm(forms.Form):
    yes_no = (("0", "No"), ("1", "Yes"))
    report_name = forms.CharField(required=False, max_length=100)
    include_finding_notes = forms.ChoiceField(required=False, choices=yes_no)
    include_finding_images = forms.ChoiceField(choices=yes_no, label="Finding Images")
    report_type = forms.ChoiceField(choices=(("HTML", "HTML"),))


from dojo.benchmark.ui.forms import (  # noqa: E402, F401 -- backward compat
    Benchmark_Product_SummaryForm,
    Benchmark_RequirementForm,
    BenchmarkForm,
    DeleteBenchmarkForm,
)


class RegulationForm(forms.ModelForm):
    class Meta:
        model = Regulation
        exclude = ["product"]


class AppAnalysisForm(forms.ModelForm):
    user = forms.ModelChoiceField(queryset=Dojo_User.objects.exclude(is_active=False).order_by("first_name", "last_name"), required=True)

    class Meta:
        model = App_Analysis
        exclude = ["product"]


class DeleteAppAnalysisForm(forms.ModelForm):
    class Meta:
        model = App_Analysis
        exclude = ["product", "tags"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["name"].disabled = True
        self.fields["user"].disabled = True
        self.fields["confidence"].disabled = True
        self.fields["version"].disabled = True
        self.fields["icon"].disabled = True
        self.fields["website"].disabled = True
        self.fields["website_found"].disabled = True


class SLAConfigForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # if this sla config has findings being asynchronously updated, disable the days by severity fields
        if self.instance.async_updating:
            msg = (
                "Finding SLA expiration dates are currently being recalculated. "
                "This field cannot be changed until the calculation is complete."
            )
            self.fields["critical"].disabled = True
            self.fields["enforce_critical"].disabled = True
            self.fields["critical"].widget.attrs["message"] = msg
            self.fields["high"].disabled = True
            self.fields["enforce_high"].disabled = True
            self.fields["high"].widget.attrs["message"] = msg
            self.fields["medium"].disabled = True
            self.fields["enforce_medium"].disabled = True
            self.fields["medium"].widget.attrs["message"] = msg
            self.fields["low"].disabled = True
            self.fields["enforce_low"].disabled = True
            self.fields["low"].widget.attrs["message"] = msg
            self.fields["restart_sla_on_reactivation"].disabled = True
            self.fields["restart_sla_on_reactivation"].widget.attrs["message"] = msg

    class Meta:
        model = SLA_Configuration
        fields = ["name", "description", "critical", "enforce_critical", "high", "enforce_high", "medium", "enforce_medium", "low", "enforce_low", "restart_sla_on_reactivation"]


class DeleteSLAConfigForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = SLA_Configuration
        fields = ["id"]


class DeleteObjectsSettingsForm(forms.ModelForm):
    id = forms.IntegerField(required=True,
                            widget=forms.widgets.HiddenInput())

    class Meta:
        model = Objects_Product
        fields = ["id"]


class ObjectSettingsForm(forms.ModelForm):

    # tags = forms.CharField(widget=forms.SelectMultiple(choices=[]),
    #                        required=False,
    #                        help_text="Add tags that help describe this object.  "
    #                                  "Choose from the list or add new tags.  Press TAB key to add.")

    class Meta:
        model = Objects_Product
        fields = ["path", "folder", "artifact", "name", "review_status", "tags"]
        exclude = ["product"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def clean(self):
        return self.cleaned_data


from dojo.notifications.ui.forms import (  # noqa: E402, F401  -- backward compat
    DeleteNotificationsWebhookForm,
    NotificationsForm,
    NotificationsWebhookForm,
    ProductNotificationsForm,
)


class AjaxChoiceField(forms.ChoiceField):
    def valid_value(self, value):
        return True


class LoginBanner(forms.Form):
    banner_enable = forms.BooleanField(
        label="Enable login banner",
        initial=False,
        required=False,
        help_text="Tick this box to enable a text banner on the login page",
    )

    banner_message = forms.CharField(
        required=False,
        label="Message to display on the login page",
    )

    def clean(self):
        return super().clean()


class AnnouncementCreateForm(forms.ModelForm):
    class Meta:
        model = Announcement
        fields = "__all__"


class AnnouncementRemoveForm(AnnouncementCreateForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["dismissable"].disabled = True
        self.fields["message"].disabled = True
        self.fields["style"].disabled = True


class ConfigurationPermissionsForm(forms.Form):

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user", None)
        self.group = kwargs.pop("group", None)
        super().__init__(*args, **kwargs)

        self.permission_fields = get_configuration_permissions_fields()

        for permission_field in self.permission_fields:
            for codename in permission_field.codenames():
                self.fields[codename] = forms.BooleanField(required=False)
                if not get_current_user().has_perm("auth.change_permission"):
                    self.fields[codename].disabled = True

        permissions_list = Permission.objects.all()
        self.permissions = {}
        for permission in permissions_list:
            self.permissions[permission.codename] = permission

    def save(self):
        if get_current_user().is_superuser:
            for permission_field in self.permission_fields:
                for codename in permission_field.codenames():
                    self.set_permission(codename)

    def set_permission(self, codename):
        if self.cleaned_data[codename]:
            # Checkbox is set
            if self.user:
                self.user.user_permissions.add(self.permissions[codename])
            elif self.group:
                self.group.auth_group.permissions.add(self.permissions[codename])
            else:
                msg = "Neither user or group are set"
                raise Exception(msg)
        # Checkbox is unset
        elif self.user:
            self.user.user_permissions.remove(self.permissions[codename])
        elif self.group:
            self.group.auth_group.permissions.remove(self.permissions[codename])
        else:
            msg = "Neither user or group are set"
            raise Exception(msg)
