import logging
import os
import pickle
import re
import warnings
from datetime import date, datetime
from pathlib import Path

import tagulous
from crispy_forms.bootstrap import InlineCheckboxes, InlineRadios
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout
from crum import get_current_user
from dateutil.relativedelta import relativedelta
from django import forms
from django.conf import settings
from django.contrib.auth.models import Permission
from django.contrib.auth.password_validation import validate_password
from django.core import validators
from django.core.exceptions import ValidationError
from django.db.models import Count, Q
from django.forms import modelformset_factory
from django.forms.widgets import Select, Widget
from django.urls import reverse
from django.utils import timezone
from django.utils.dates import MONTHS
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _
from polymorphic.base import ManagerInheritanceWarning
from tagulous.forms import TagField, TagWidget
from tagulous.models import TagOptions

import dojo.jira_link.helper as jira_helper
from dojo.authorization.authorization import user_has_configuration_permission
from dojo.authorization.roles_permissions import Permissions
from dojo.endpoint.utils import endpoint_filter, endpoint_get_or_create, validate_endpoints_to_add
from dojo.engagement.queries import get_authorized_engagements
from dojo.finding.queries import get_authorized_findings
from dojo.group.queries import get_authorized_groups, get_group_member_roles
from dojo.models import (
    EFFORT_FOR_FIXING_CHOICES,
    SEVERITY_CHOICES,
    Announcement,
    Answered_Survey,
    App_Analysis,
    Benchmark_Product,
    Benchmark_Product_Summary,
    Benchmark_Requirement,
    Check_List,
    Choice,
    ChoiceAnswer,
    ChoiceQuestion,
    Cred_Mapping,
    Cred_User,
    Development_Environment,
    Dojo_Group,
    Dojo_Group_Member,
    Dojo_User,
    DojoMeta,
    Endpoint,
    Engagement,
    Engagement_Presets,
    Engagement_Survey,
    FileUpload,
    Finding,
    Finding_Group,
    Finding_Template,
    General_Survey,
    GITHUB_Conf,
    GITHUB_Issue,
    GITHUB_PKey,
    Global_Role,
    JIRA_Instance,
    JIRA_Issue,
    JIRA_Project,
    Note_Type,
    Notes,
    Notification_Webhooks,
    Notifications,
    Objects_Product,
    Product,
    Product_API_Scan_Configuration,
    Product_Group,
    Product_Member,
    Product_Type,
    Product_Type_Group,
    Product_Type_Member,
    Question,
    Regulation,
    Risk_Acceptance,
    SLA_Configuration,
    Stub_Finding,
    System_Settings,
    Test,
    Test_Type,
    TextAnswer,
    TextQuestion,
    Tool_Configuration,
    Tool_Product_Settings,
    Tool_Type,
    User,
    UserContactInfo,
)
from dojo.product.queries import get_authorized_products
from dojo.product_type.queries import get_authorized_product_types
from dojo.tools.factory import get_choices_sorted, requires_file, requires_tool_type
from dojo.user.queries import get_authorized_users, get_authorized_users_for_product_and_product_type
from dojo.user.utils import get_configuration_permissions_fields
from dojo.utils import (
    get_password_requirements_string,
    get_product,
    get_system_setting,
    is_finding_groups_enabled,
    is_scan_file_too_large,
)
from dojo.validators import ImporterFileExtensionValidator, tag_validator
from dojo.widgets import TableCheckboxWidget

logger = logging.getLogger(__name__)

RE_DATE = re.compile(r"(\d{4})-(\d\d?)-(\d\d?)$")

FINDING_STATUS = (
    ("verified", "Verified"),
    ("false_p", "False Positive"),
    ("duplicate", "Duplicate"),
    ("out_of_scope", "Out of Scope"),
)

CVSS_CALCULATOR_URLS = {
    "https://www.first.org/cvss/calculator/3-0": "CVSS3 Calculator by FIRST",
    "https://www.first.org/cvss/calculator/4-0": "CVSS4 Calculator by FIRST",
    "https://www.metaeffekt.com/security/cvss/calculator/": "CVSS2/3/4 Calculator by Metaeffekt",
}


vulnerability_ids_field = forms.CharField(
    max_length=5000,
    required=False,
    label="Vulnerability Ids",
    help_text="Ids of vulnerabilities in security advisories associated with this finding. Can be Common Vulnerabilities and Exposures (CVE) or from other sources."
    "You may enter one vulnerability id per line.",
    widget=forms.widgets.Textarea(attrs={"rows": "3", "cols": "400"}),
)

EFFORT_FOR_FIXING_INVALID_CHOICE = _("Select valid choice: Low,Medium,High")

from dojo.url.models import URL
from dojo.location.models import Location


class URLForm(forms.ModelForm):
    tags = TagField(
        label="Tags",
        required=False,
        help_text="Add tags that help describe this endpoint. Choose from the list or add new tags. Press Enter key to add.",
        autocomplete_tags=Location.tags.tag_model.objects.all().order_by("name"),
    )

    class Meta:
        model = URL
        exclude = ["location", "host_validation_failure"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance is not None and hasattr(self.instance, "location"):
            self.fields["tags"].initial = self.instance.location.tags.all()

    def clean_tags(self):
        tag_validator(self.cleaned_data.get("tags"))
        return self.cleaned_data.get("tags")

    def save(self, commit: bool = True) -> URL:
        url = super().save(commit=commit)
        if commit:
            url.location.tags.set(self.cleaned_data["tags"])
        return url


class DeleteURLForm(forms.ModelForm):
    id = forms.IntegerField(required=True, widget=forms.widgets.HiddenInput())

    class Meta:
        model = URL
        fields = ["id"]
