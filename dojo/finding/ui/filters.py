from datetime import timedelta

from django import forms
from django.conf import settings
from django.db.models import Q
from django.forms import HiddenInput
from django.utils.translation import gettext_lazy as _
from django_filters import (
    BooleanFilter,
    CharFilter,
    ChoiceFilter,
    DateFilter,
    DateFromToRangeFilter,
    DateTimeFilter,
    FilterSet,
    ModelChoiceFilter,
    ModelMultipleChoiceFilter,
    MultipleChoiceFilter,
    NumberFilter,
    OrderingFilter,
)

from dojo.engagement.queries import get_authorized_engagements
from dojo.filters import (
    DateRangeFilter,
    DateRangeOmniFilter,
    DojoFilter,
    FindingHasJIRAFilter,
    FindingSLAFilter,
    FindingStatusFilter,
    FindingTagFilter,
    FindingTagStringFilter,
    MetricsDateRangeFilter,
    PercentageFilter,
    PercentageRangeFilter,
    ReportBooleanFilter,
    ReportRiskAcceptanceFilter,
    custom_vulnerability_id_filter,
    cwe_options,
    filter_endpoints_base,
    filter_endpoints_host_base,
    get_finding_filterset_fields,
    vulnerability_id_filter,
)
from dojo.finding.queries import (
    get_authorized_findings_for_queryset,
)
from dojo.finding_group.queries import get_authorized_finding_groups_for_queryset
from dojo.labels import get_labels
from dojo.location.status import FindingLocationStatus
from dojo.models import (
    EFFORT_FOR_FIXING_CHOICES,
    SEVERITY_CHOICES,
    Dojo_User,
    Endpoint,
    Engagement,
    Finding,
    Finding_Group,
    Finding_Template,
    Product,
    Product_Type,
    Risk_Acceptance,
    Test,
    Test_Type,
)
from dojo.product.queries import get_authorized_products
from dojo.product_type.queries import get_authorized_product_types
from dojo.risk_acceptance.queries import get_authorized_risk_acceptances
from dojo.test.queries import get_authorized_tests
from dojo.user.queries import get_authorized_users
from dojo.utils import get_system_setting, get_visible_scan_types, is_finding_groups_enabled

labels = get_labels()


class FindingFilterHelper(FilterSet):
    title = CharFilter(lookup_expr="icontains")
    date = DateRangeFilter(field_name="date", label="Date Discovered")
    on = DateFilter(field_name="date", lookup_expr="exact", label="Discovered On")
    before = DateFilter(field_name="date", lookup_expr="lt", label="Discovered Before")
    after = DateFilter(field_name="date", lookup_expr="gt", label="Discovered After")
    last_reviewed = DateRangeFilter()
    last_status_update = DateRangeFilter()
    cwe = MultipleChoiceFilter(choices=[])
    vulnerability_id = CharFilter(method=vulnerability_id_filter, label="Vulnerability Id")
    severity = MultipleChoiceFilter(choices=SEVERITY_CHOICES)
    duplicate = ReportBooleanFilter()
    is_mitigated = ReportBooleanFilter()
    fix_available = ReportBooleanFilter()
    mitigation = CharFilter(lookup_expr="icontains")
    mitigation_available = BooleanFilter(method="filter_mitigation_available", label="Mitigation Available")
    mitigated = DateRangeFilter(field_name="mitigated", label="Mitigated Date")
    mitigated_on = DateTimeFilter(field_name="mitigated", lookup_expr="exact", label="Mitigated On", method="filter_mitigated_on")
    mitigated_before = DateTimeFilter(field_name="mitigated", lookup_expr="lt", label="Mitigated Before")
    mitigated_after = DateTimeFilter(field_name="mitigated", lookup_expr="gt", label="Mitigated After", method="filter_mitigated_after")
    planned_remediation_date = DateRangeOmniFilter()
    planned_remediation_version = CharFilter(lookup_expr="icontains", label=_("Planned remediation version"))
    file_path = CharFilter(lookup_expr="icontains")
    param = CharFilter(lookup_expr="icontains")
    payload = CharFilter(lookup_expr="icontains")
    test__test_type = ModelMultipleChoiceFilter(queryset=Test_Type.objects.all(), label="Test Type")
    service = CharFilter(lookup_expr="icontains")
    test__engagement__version = CharFilter(lookup_expr="icontains", label="Engagement Version")
    test__version = CharFilter(lookup_expr="icontains", label="Test Version")
    risk_acceptance = ReportRiskAcceptanceFilter(label="Risk Accepted")
    effort_for_fixing = MultipleChoiceFilter(choices=EFFORT_FOR_FIXING_CHOICES)
    test_import_finding_action__test_import = NumberFilter(widget=HiddenInput())
    status = FindingStatusFilter(label="Status")
    test__engagement__product__lifecycle = MultipleChoiceFilter(
        choices=Product.LIFECYCLE_CHOICES,
        label=labels.ASSET_LIFECYCLE_LABEL)
    if settings.V3_FEATURE_LOCATIONS:
        location_status = MultipleChoiceFilter(
            field_name="locations__status",
            choices=FindingLocationStatus.choices,
            help_text="Status of the Location from the Findings relationship",
        )
        endpoints__host = CharFilter(
            field_name="locations__location__url__host", method="filter_endpoints_host", label="Endpoint Host",
        )
        endpoints = NumberFilter(field_name="locations__location", method="filter_endpoints", widget=HiddenInput())

        def filter_endpoints_host(self, queryset, name, value):
            return filter_endpoints_host_base(
                queryset,
                name,
                value,
                endpoint_id=self.data.get("endpoints"),
                statuses=self.data.getlist("location_status"),
            )

        def filter_endpoints(self, queryset, name, value):
            return filter_endpoints_base(
                queryset,
                name,
                value,
                statuses=self.data.getlist("location_status"),
                host=self.data.get("endpoints__host"),
            )
    else:
        # TODO: Delete this after the move to Locations
        endpoints__host = CharFilter(lookup_expr="icontains", label="Endpoint Host")
        endpoints = NumberFilter(widget=HiddenInput())

    has_component = BooleanFilter(
        field_name="component_name",
        lookup_expr="isnull",
        exclude=True,
        label="Has Component")
    has_notes = BooleanFilter(
        field_name="notes",
        lookup_expr="isnull",
        exclude=True,
        label="Has notes")

    if is_finding_groups_enabled():
        has_finding_group = BooleanFilter(
            field_name="finding_group",
            lookup_expr="isnull",
            exclude=True,
            label="Is Grouped")

    if get_system_setting("enable_jira"):
        has_jira_issue = BooleanFilter(
            field_name="jira_issue",
            lookup_expr="isnull",
            exclude=True,
            label="Has JIRA")
        jira_creation = DateRangeFilter(field_name="jira_issue__jira_creation", label="JIRA Creation")
        jira_change = DateRangeFilter(field_name="jira_issue__jira_change", label="JIRA Updated")
        jira_issue__jira_key = CharFilter(field_name="jira_issue__jira_key", lookup_expr="icontains", label="JIRA issue")

        if is_finding_groups_enabled():
            has_jira_group_issue = BooleanFilter(
                field_name="finding_group__jira_issue",
                lookup_expr="isnull",
                exclude=True,
                label="Has Group JIRA")
        has_any_jira_issue = FindingHasJIRAFilter(
            label="Has Any JIRA Issue",
            help_text="Matches JIRA issues linked to the finding itself or to the finding's group.",
        )

    outside_of_sla = FindingSLAFilter(label="Outside of SLA")
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")
    epss_score = PercentageFilter(field_name="epss_score", label="EPSS score")
    epss_score_range = PercentageRangeFilter(
        field_name="epss_score",
        label="EPSS score range",
        help_text=(
            "The range of EPSS score percentages to filter on; the left input is a lower bound, "
            "the right is an upper bound. Leaving one empty will skip that bound (e.g., leaving "
            "the lower bound input empty will filter only on the upper bound -- filtering on "
            '"less than or equal").'
        ))
    epss_percentile = PercentageFilter(field_name="epss_percentile", label="EPSS percentile")
    epss_percentile_range = PercentageRangeFilter(
        field_name="epss_percentile",
        label="EPSS percentile range",
        help_text=(
            "The range of EPSS percentiles to filter on; the left input is a lower bound, the right "
            "is an upper bound. Leaving one empty will skip that bound (e.g., leaving the lower bound "
            'input empty will filter only on the upper bound -- filtering on "less than or equal").'
        ))
    kev_date = DateFilter(field_name="kev_date", lookup_expr="exact", label="Added to KEV On")
    kev_before = DateFilter(field_name="kev_date", lookup_expr="lt", label="Added to KEV Before")
    kev_after = DateFilter(field_name="kev_date", lookup_expr="gt", label="Added to KEV After")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("numerical_severity", "numerical_severity"),
            ("date", "date"),
            ("mitigated", "mitigated"),
            ("fix_available", "fix_available"),
            ("risk_acceptance__created__date",
             "risk_acceptance__created__date"),
            ("last_reviewed", "last_reviewed"),
            ("planned_remediation_date", "planned_remediation_date"),
            ("planned_remediation_version", "planned_remediation_version"),
            ("title", "title"),
            ("test__engagement__product__name",
             "test__engagement__product__name"),
            ("service", "service"),
            ("sla_age_days", "sla_age_days"),
            ("epss_score", "epss_score"),
            ("epss_percentile", "epss_percentile"),
            ("known_exploited", "known_exploited"),
            ("ransomware_used", "ransomware_used"),
            ("kev_date", "kev_date"),
        ),
        field_labels={
            "numerical_severity": "Severity",
            "date": "Date",
            "risk_acceptance__created__date": "Acceptance Date",
            "mitigated": "Mitigated Date",
            "fix_available": "Fix Available",
            "title": "Finding Name",
            "test__engagement__product__name": labels.ASSET_FILTERS_NAME_LABEL,
            "epss_score": "EPSS Score",
            "epss_percentile": "EPSS Percentile",
            "known_exploited": "Known Exploited",
            "ransomware_used": "Ransomware Used",
            "kev_date": "Date added to KEV",
            "sla_age_days": "SLA age (days)",
            "planned_remediation_date": "Planned Remediation",
            "planned_remediation_version": "Planned remediation version",
        },
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if "test__test_type" in self.form.fields:
            self.form.fields["test__test_type"].queryset = get_visible_scan_types()

    def set_date_fields(self, *args: list, **kwargs: dict):
        date_input_widget = forms.DateInput(attrs={"class": "datepicker", "placeholder": "YYYY-MM-DD"}, format="%Y-%m-%d")
        self.form.fields["on"].widget = date_input_widget
        self.form.fields["before"].widget = date_input_widget
        self.form.fields["after"].widget = date_input_widget
        self.form.fields["kev_date"].widget = date_input_widget
        self.form.fields["kev_before"].widget = date_input_widget
        self.form.fields["kev_after"].widget = date_input_widget
        self.form.fields["mitigated_on"].widget = date_input_widget
        self.form.fields["mitigated_before"].widget = date_input_widget
        self.form.fields["mitigated_after"].widget = date_input_widget
        self.form.fields["cwe"].choices = cwe_options(self.queryset)

    def filter_mitigated_after(self, queryset, name, value):
        if value.hour == 0 and value.minute == 0 and value.second == 0:
            value = value.replace(hour=23, minute=59, second=59)

        return queryset.filter(mitigated__gt=value)

    def filter_mitigated_on(self, queryset, name, value):
        if value.hour == 0 and value.minute == 0 and value.second == 0:
            # we have a simple date without a time, lets get a range from this morning to tonight at 23:59:59:999
            nextday = value + timedelta(days=1)
            return queryset.filter(mitigated__gte=value, mitigated__lt=nextday)

        return queryset.filter(mitigated=value)

    def filter_mitigation_available(self, queryset, name, value):
        if value:
            return queryset.exclude(mitigation__isnull=True).exclude(mitigation__exact="")
        return queryset.filter(Q(mitigation__isnull=True) | Q(mitigation__exact=""))


def get_finding_group_queryset_for_context(pid=None, eid=None, tid=None):
    """
    Helper function to build finding group queryset based on context hierarchy.
    Context priority: test > engagement > product > global

    Args:
        pid: Product ID (least specific)
        eid: Engagement ID
        tid: Test ID (most specific)

    Returns:
        QuerySet of Finding_Group filtered by context

    """
    if tid is not None:
        # Most specific: filter by test
        return Finding_Group.objects.filter(test_id=tid).only("id", "name")
    if eid is not None:
        # Filter by engagement's tests
        return Finding_Group.objects.filter(test__engagement_id=eid).only("id", "name")
    if pid is not None:
        # Filter by product's tests
        return Finding_Group.objects.filter(test__engagement__product_id=pid).only("id", "name")
    # Global: return all (authorization will be applied separately)
    return Finding_Group.objects.all().only("id", "name")


class FindingFilterWithoutObjectLookups(FindingFilterHelper, FindingTagStringFilter):
    test__engagement__product__prod_type = NumberFilter(widget=HiddenInput())
    test__engagement__product = NumberFilter(widget=HiddenInput())
    reporter = CharFilter(
        field_name="reporter__username",
        lookup_expr="iexact",
        label="Reporter Username",
        help_text="Search for Reporter names that are an exact match")
    reporter_contains = CharFilter(
        field_name="reporter__username",
        lookup_expr="icontains",
        label="Reporter Username Contains",
        help_text="Search for Reporter names that contain a given pattern")
    reviewers = CharFilter(
        field_name="reviewers__username",
        lookup_expr="iexact",
        label="Reviewer Username",
        help_text="Search for Reviewer names that are an exact match")
    reviewers_contains = CharFilter(
        field_name="reviewers__username",
        lookup_expr="icontains",
        label="Reviewer Username Contains",
        help_text="Search for Reviewer usernames that contain a given pattern")
    test__engagement__product__prod_type__name = CharFilter(
        field_name="test__engagement__product__prod_type__name",
        lookup_expr="iexact",
        label=labels.ORG_FILTERS_NAME_LABEL,
        help_text=labels.ORG_FILTERS_NAME_HELP)
    test__engagement__product__prod_type__name_contains = CharFilter(
        field_name="test__engagement__product__prod_type__name",
        lookup_expr="icontains",
        label=labels.ORG_FILTERS_NAME_CONTAINS_LABEL,
        help_text=labels.ORG_FILTERS_NAME_CONTAINS_HELP)
    test__engagement__product__name = CharFilter(
        field_name="test__engagement__product__name",
        lookup_expr="iexact",
        label=labels.ASSET_FILTERS_NAME_LABEL,
        help_text=labels.ASSET_FILTERS_NAME_HELP)
    test__engagement__product__name_contains = CharFilter(
        field_name="test__engagement__product__name",
        lookup_expr="icontains",
        label=labels.ASSET_FILTERS_NAME_CONTAINS_LABEL,
        help_text=labels.ASSET_FILTERS_NAME_CONTAINS_HELP)
    test__engagement__name = CharFilter(
        field_name="test__engagement__name",
        lookup_expr="iexact",
        label="Engagement Name",
        help_text="Search for Engagement names that are an exact match")
    test__engagement__name_contains = CharFilter(
        field_name="test__engagement__name",
        lookup_expr="icontains",
        label="Engagement name Contains",
        help_text="Search for Engagement names that contain a given pattern")
    test__name = CharFilter(
        field_name="test__title",
        lookup_expr="iexact",
        label="Test Name",
        help_text="Search for Test names that are an exact match")
    test__name_contains = CharFilter(
        field_name="test__title",
        lookup_expr="icontains",
        label="Test name Contains",
        help_text="Search for Test names that contain a given pattern")

    if is_finding_groups_enabled():
        finding_group__name = CharFilter(
            field_name="finding_group__name",
            lookup_expr="iexact",
            label="Finding Group Name",
            help_text="Search for Finding Group names that are an exact match")
        finding_group__name_contains = CharFilter(
            field_name="finding_group__name",
            lookup_expr="icontains",
            label="Finding Group Name Contains",
            help_text="Search for Finding Group names that contain a given pattern")

    class Meta:
        model = Finding
        fields = get_finding_filterset_fields(filter_string_matching=True)

        exclude = ["url", "description", "mitigation", "impact",
                   "endpoints", "references",
                   "thread_id", "notes", "scanner_confidence",
                   "numerical_severity", "line", "duplicate_finding",
                   "hash_code", "reviewers", "created", "files",
                   "sla_start_date", "sla_expiration_date", "cvssv3",
                   "severity_justification", "steps_to_reproduce"]

    def __init__(self, *args, **kwargs):
        self.user = None
        self.pid = None
        self.eid = None
        self.tid = None
        if "user" in kwargs:
            self.user = kwargs.pop("user")

        if "pid" in kwargs:
            self.pid = kwargs.pop("pid")
        if "eid" in kwargs:
            self.eid = kwargs.pop("eid")
        if "tid" in kwargs:
            self.tid = kwargs.pop("tid")
        super().__init__(*args, **kwargs)
        # Set some date fields
        self.set_date_fields(*args, **kwargs)
        # Don't show the product/engagement/test filter fields when in specific context
        if self.tid or self.eid or self.pid:
            if "test__engagement__product__name" in self.form.fields:
                del self.form.fields["test__engagement__product__name"]
            if "test__engagement__product__name_contains" in self.form.fields:
                del self.form.fields["test__engagement__product__name_contains"]
            if "test__engagement__product__prod_type__name" in self.form.fields:
                del self.form.fields["test__engagement__product__prod_type__name"]
            if "test__engagement__product__prod_type__name_contains" in self.form.fields:
                del self.form.fields["test__engagement__product__prod_type__name_contains"]
        # Also hide engagement and test fields if in test or engagement  context
        if self.tid:
            if "test__engagement__name" in self.form.fields:
                del self.form.fields["test__engagement__name"]
            if "test__engagement__name_contains" in self.form.fields:
                del self.form.fields["test__engagement__name_contains"]
            if "test__name" in self.form.fields:
                del self.form.fields["test__name"]
            if "test__name_contains" in self.form.fields:
                del self.form.fields["test__name_contains"]
        elif self.eid:
            if "test__engagement__name" in self.form.fields:
                del self.form.fields["test__engagement__name"]
            if "test__engagement__name_contains" in self.form.fields:
                del self.form.fields["test__engagement__name_contains"]


class FindingFilter(FindingFilterHelper, FindingTagFilter):
    reporter = ModelMultipleChoiceFilter(queryset=Dojo_User.objects.none())
    reviewers = ModelMultipleChoiceFilter(queryset=Dojo_User.objects.none())
    test__engagement__product__prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.none(),
        label=labels.ORG_FILTERS_LABEL)
    test__engagement__product = ModelMultipleChoiceFilter(
        queryset=Product.objects.none(),
        label=labels.ASSET_FILTERS_LABEL)
    test__engagement = ModelMultipleChoiceFilter(
        queryset=Engagement.objects.none(),
        label="Engagement")
    test = ModelMultipleChoiceFilter(
        queryset=Test.objects.none(),
        label="Test")

    if is_finding_groups_enabled():
        finding_group = ModelMultipleChoiceFilter(
            queryset=Finding_Group.objects.none(),
            label="Finding Group")

    class Meta:
        model = Finding
        fields = get_finding_filterset_fields()

        exclude = ["url", "description", "mitigation", "impact",
                   "endpoints", "references",
                   "thread_id", "notes", "scanner_confidence",
                   "numerical_severity", "line", "duplicate_finding",
                   "hash_code", "reviewers", "created", "files",
                   "sla_start_date", "sla_expiration_date", "cvssv3",
                   "severity_justification", "steps_to_reproduce"]

    def __init__(self, *args, **kwargs):
        self.user = None
        self.pid = None
        self.eid = None
        self.tid = None
        if "user" in kwargs:
            self.user = kwargs.pop("user")

        if "pid" in kwargs:
            self.pid = kwargs.pop("pid")
        if "eid" in kwargs:
            self.eid = kwargs.pop("eid")
        if "tid" in kwargs:
            self.tid = kwargs.pop("tid")
        super().__init__(*args, **kwargs)
        # Set some date fields
        self.set_date_fields(*args, **kwargs)
        # Don't show the product filter on the product finding view
        self.set_related_object_fields(*args, **kwargs)

    def set_related_object_fields(self, *args: list, **kwargs: dict):
        # Use helper to get contextual finding group queryset
        finding_group_query = get_finding_group_queryset_for_context(
            pid=self.pid,
            eid=self.eid,
            tid=self.tid,
        )

        # Filter by most specific context: test > engagement > product
        if self.tid is not None:
            # Test context: filter finding groups by test
            if "test__engagement__product" in self.form.fields:
                del self.form.fields["test__engagement__product"]
            if "test__engagement__product__prod_type" in self.form.fields:
                del self.form.fields["test__engagement__product__prod_type"]
            if "test__engagement" in self.form.fields:
                del self.form.fields["test__engagement"]
            if "test" in self.form.fields:
                del self.form.fields["test"]
        elif self.eid is not None:
            # Engagement context: filter finding groups by engagement
            if "test__engagement__product" in self.form.fields:
                del self.form.fields["test__engagement__product"]
            if "test__engagement__product__prod_type" in self.form.fields:
                del self.form.fields["test__engagement__product__prod_type"]
            if "test__engagement" in self.form.fields:
                del self.form.fields["test__engagement"]
            # Filter tests by engagement - get_authorized_tests doesn't support engagement param
            engagement = Engagement.objects.filter(id=self.eid).select_related("product").first()
            if engagement:
                self.form.fields["test"].queryset = get_authorized_tests("view", product=engagement.product).filter(engagement_id=self.eid).prefetch_related("test_type")
        elif self.pid is not None:
            # Product context: filter finding groups by product
            if "test__engagement__product" in self.form.fields:
                del self.form.fields["test__engagement__product"]
            if "test__engagement__product__prod_type" in self.form.fields:
                del self.form.fields["test__engagement__product__prod_type"]
            # TODO: add authorized check to be sure
            if "test__engagement" in self.form.fields:
                self.form.fields["test__engagement"].queryset = Engagement.objects.filter(
                    product_id=self.pid,
                ).all()
            if "test" in self.form.fields:
                self.form.fields["test"].queryset = get_authorized_tests("view", product=self.pid).prefetch_related("test_type")
        else:
            # Global context: show all authorized finding groups
            self.form.fields[
                "test__engagement__product__prod_type"].queryset = get_authorized_product_types("view")
            self.form.fields["test__engagement"].queryset = get_authorized_engagements("view")
            if "test" in self.form.fields:
                del self.form.fields["test"]

        if self.form.fields.get("test__engagement__product"):
            self.form.fields["test__engagement__product"].queryset = get_authorized_products("view")
        if self.form.fields.get("finding_group", None):
            self.form.fields["finding_group"].queryset = get_authorized_finding_groups_for_queryset("view", finding_group_query, user=self.user)
        self.form.fields["reporter"].queryset = get_authorized_users("view")
        self.form.fields["reviewers"].queryset = self.form.fields["reporter"].queryset


class FindingGroupsFilter(FilterSet):
    name = CharFilter(lookup_expr="icontains", label="Name")
    severity = ChoiceFilter(
        choices=[
            ("Low", "Low"),
            ("Medium", "Medium"),
            ("High", "High"),
            ("Critical", "Critical"),
        ],
        label="Min Severity",
    )
    engagement = ModelMultipleChoiceFilter(queryset=Engagement.objects.none(), label="Engagement")
    product = ModelMultipleChoiceFilter(queryset=Product.objects.none(), label=labels.ASSET_LABEL)

    class Meta:
        model = Finding
        fields = ["name", "severity", "engagement", "product"]

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user", None)
        self.pid = kwargs.pop("pid", None)
        super().__init__(*args, **kwargs)
        self.set_related_object_fields()

    def set_related_object_fields(self):
        if self.pid is not None:
            self.form.fields["engagement"].queryset = Engagement.objects.filter(product_id=self.pid)
            if "product" in self.form.fields:
                del self.form.fields["product"]
        else:
            self.form.fields["product"].queryset = get_authorized_products("view")
            self.form.fields["engagement"].queryset = get_authorized_engagements("view")


class AcceptedFindingFilter(FindingFilter):
    risk_acceptance__created__date = DateRangeFilter(label="Acceptance Date")
    risk_acceptance__owner = ModelMultipleChoiceFilter(
            queryset=Dojo_User.objects.none(),
            label="Risk Acceptance Owner")
    risk_acceptance = ModelMultipleChoiceFilter(
        queryset=Risk_Acceptance.objects.none(),
        label="Accepted By")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.form.fields["risk_acceptance__owner"].queryset = get_authorized_users("view")
        self.form.fields["risk_acceptance"].queryset = get_authorized_risk_acceptances("edit")


class AcceptedFindingFilterWithoutObjectLookups(FindingFilterWithoutObjectLookups):
    risk_acceptance__created__date = DateRangeFilter(label="Acceptance Date")
    risk_acceptance__owner = CharFilter(
        field_name="risk_acceptance__owner__username",
        lookup_expr="iexact",
        label="Risk Acceptance Owner Username",
        help_text="Search for Risk Acceptance Owners username that are an exact match")
    risk_acceptance__owner_contains = CharFilter(
        field_name="risk_acceptance__owner__username",
        lookup_expr="icontains",
        label="Risk Acceptance Owner Username Contains",
        help_text="Search for Risk Acceptance Owners username that contain a given pattern")
    risk_acceptance__name = CharFilter(
        field_name="risk_acceptance__name",
        lookup_expr="iexact",
        label="Risk Acceptance Name",
        help_text="Search for Risk Acceptance name that are an exact match")
    risk_acceptance__name_contains = CharFilter(
        field_name="risk_acceptance__name",
        lookup_expr="icontains",
        label="Risk Acceptance Name",
        help_text="Search for Risk Acceptance name contain a given pattern")


class SimilarFindingHelper(FilterSet):
    hash_code = MultipleChoiceFilter()
    vulnerability_ids = CharFilter(method=custom_vulnerability_id_filter, label="Vulnerability Ids")

    def update_data(self, data: dict, *args: list, **kwargs: dict):
        # if filterset is bound, use initial values as defaults
        # because of this, we can't rely on the self.form.has_changed
        self.has_changed = True
        if not data and self.finding:
            # get a mutable copy of the QueryDict
            data = data.copy()

            data["vulnerability_ids"] = ",".join(self.finding.vulnerability_ids)
            data["cwe"] = self.finding.cwe
            data["file_path"] = self.finding.file_path
            data["line"] = self.finding.line
            data["unique_id_from_tool"] = self.finding.unique_id_from_tool
            data["test__test_type"] = self.finding.test.test_type
            data["test__engagement__product"] = self.finding.test.engagement.product
            data["test__engagement__product__prod_type"] = self.finding.test.engagement.product.prod_type

            self.has_changed = False

    def set_hash_codes(self, *args: list, **kwargs: dict):
        if self.finding and self.finding.hash_code:
            self.form.fields["hash_code"] = forms.MultipleChoiceField(choices=[(self.finding.hash_code, self.finding.hash_code[:24] + "...")], required=False, initial=[])

    def filter_queryset(self, *args: list, **kwargs: dict):
        queryset = super().filter_queryset(*args, **kwargs)
        queryset = get_authorized_findings_for_queryset("view", queryset, self.user)
        return queryset.exclude(pk=self.finding.pk)


class SimilarFindingFilter(FindingFilter, SimilarFindingHelper):
    class Meta(FindingFilter.Meta):
        model = Finding
        # slightly different fields from FindingFilter, but keep the same ordering for UI consistency
        fields = get_finding_filterset_fields(similar=True)

    def __init__(self, data=None, *args, **kwargs):
        self.user = None
        if "user" in kwargs:
            self.user = kwargs.pop("user")
        self.finding = None
        if "finding" in kwargs:
            self.finding = kwargs.pop("finding")
        self.update_data(data, *args, **kwargs)
        super().__init__(data, *args, **kwargs)
        self.set_hash_codes(*args, **kwargs)


class SimilarFindingFilterWithoutObjectLookups(FindingFilterWithoutObjectLookups, SimilarFindingHelper):
    class Meta(FindingFilterWithoutObjectLookups.Meta):
        model = Finding
        # slightly different fields from FindingFilter, but keep the same ordering for UI consistency
        fields = get_finding_filterset_fields(similar=True, filter_string_matching=True)

    def __init__(self, data=None, *args, **kwargs):
        self.user = None
        if "user" in kwargs:
            self.user = kwargs.pop("user")
        self.finding = None
        if "finding" in kwargs:
            self.finding = kwargs.pop("finding")
        self.update_data(data, *args, **kwargs)
        super().__init__(data, *args, **kwargs)
        self.set_hash_codes(*args, **kwargs)


class TemplateFindingFilter(DojoFilter):
    title = CharFilter(lookup_expr="icontains")
    cwe = MultipleChoiceFilter(choices=[])
    severity = MultipleChoiceFilter(choices=SEVERITY_CHOICES)

    tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        queryset=Finding.tags.tag_model.objects.all().order_by("name"),
        # label='tags', # doesn't work with tagulous, need to set in __init__ below
    )

    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Tag name contains")

    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        exclude=True,
        queryset=Finding.tags.tag_model.objects.all().order_by("name"),
        # label='tags', # doesn't work with tagulous, need to set in __init__ below
    )

    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("cwe", "cwe"),
            ("title", "title"),
            ("numerical_severity", "numerical_severity"),
        ),
        field_labels={
            "numerical_severity": "Severity",
        },
    )

    class Meta:
        model = Finding_Template
        exclude = ["description", "mitigation", "impact",
                   "references", "numerical_severity"]

    not_test__tags = ModelMultipleChoiceFilter(
        field_name="test__tags__name",
        to_field_name="name",
        exclude=True,
        label="Test without tags",
        queryset=Test.tags.tag_model.objects.all().order_by("name"),
        # label='tags', # doesn't work with tagulous, need to set in __init__ below
    )

    not_test__engagement__tags = ModelMultipleChoiceFilter(
        field_name="test__engagement__tags__name",
        to_field_name="name",
        exclude=True,
        label="Engagement without tags",
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"),
        # label='tags', # doesn't work with tagulous, need to set in __init__ below
    )

    not_test__engagement__product__tags = ModelMultipleChoiceFilter(
        field_name="test__engagement__product__tags__name",
        to_field_name="name",
        exclude=True,
        label=labels.ASSET_FILTERS_WITHOUT_TAGS_LABEL,
        queryset=Product.tags.tag_model.objects.all().order_by("name"),
        # label='tags', # doesn't work with tagulous, need to set in __init__ below
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.form.fields["cwe"].choices = cwe_options(self.queryset)


class MetricsFindingFilter(FindingFilter):
    start_date = DateFilter(field_name="date", label="Start Date", lookup_expr=("gt"))
    end_date = DateFilter(field_name="date", label="End Date", lookup_expr=("lt"))
    date = MetricsDateRangeFilter()
    vulnerability_id = CharFilter(method=vulnerability_id_filter, label="Vulnerability Id")

    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        exclude=True,
        queryset=Endpoint.tags.tag_model.objects.all().order_by("name"),
        # label='tags', # doesn't work with tagulous, need to set in __init__ below
    )

    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)

    def __init__(self, *args, **kwargs):
        if args[0]:
            if args[0].get("start_date", "") or args[0].get("end_date", ""):
                args[0]._mutable = True
                args[0]["date"] = 8
                args[0]._mutable = False

        super().__init__(*args, **kwargs)

    class Meta(FindingFilter.Meta):
        model = Finding
        fields = get_finding_filterset_fields(metrics=True)


class MetricsFindingFilterWithoutObjectLookups(FindingFilterWithoutObjectLookups):
    start_date = DateFilter(field_name="date", label="Start Date", lookup_expr=("gt"))
    end_date = DateFilter(field_name="date", label="End Date", lookup_expr=("lt"))
    date = MetricsDateRangeFilter()
    vulnerability_id = CharFilter(method=vulnerability_id_filter, label="Vulnerability Id")

    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        exclude=True,
        queryset=Endpoint.tags.tag_model.objects.all().order_by("name"),
        # label='tags', # doesn't work with tagulous, need to set in __init__ below
    )

    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)

    def __init__(self, *args, **kwargs):
        if args[0]:
            if args[0].get("start_date", "") or args[0].get("end_date", ""):
                args[0]._mutable = True
                args[0]["date"] = 8
                args[0]._mutable = False

        super().__init__(*args, **kwargs)

    class Meta(FindingFilterWithoutObjectLookups.Meta):
        model = Finding
        fields = get_finding_filterset_fields(metrics=True, filter_string_matching=True)


class ReportFindingFilterHelper(FilterSet):
    title = CharFilter(lookup_expr="icontains", label="Name")
    date = DateFromToRangeFilter(field_name="date", label="Date Discovered")
    date_recent = DateRangeFilter(field_name="date", label="Relative Date")
    severity = MultipleChoiceFilter(choices=SEVERITY_CHOICES)
    active = ReportBooleanFilter()
    is_mitigated = ReportBooleanFilter()
    mitigated = DateRangeFilter(label="Mitigated Date")
    verified = ReportBooleanFilter()
    false_p = ReportBooleanFilter(label="False Positive")
    risk_acceptance = ReportRiskAcceptanceFilter(label="Risk Accepted")
    duplicate = ReportBooleanFilter()
    out_of_scope = ReportBooleanFilter()
    outside_of_sla = FindingSLAFilter(label="Outside of SLA")
    file_path = CharFilter(lookup_expr="icontains")
    mitigation_available = BooleanFilter(method="filter_mitigation_available", label="Mitigation Available")

    o = OrderingFilter(
        fields=(
            ("title", "title"),
            ("date", "date"),
            ("fix_available", "fix_available"),
            ("numerical_severity", "numerical_severity"),
            ("epss_score", "epss_score"),
            ("epss_percentile", "epss_percentile"),
            ("test__engagement__product__name", "test__engagement__product__name"),
        ),
    )

    class Meta:
        model = Finding
        # exclude sonarqube issue as by default it will show all without checking permissions
        exclude = ["date", "cwe", "url", "description", "mitigation", "impact",
                   "references", "sonarqube_issue", "duplicate_finding",
                   "thread_id", "notes", "inherited_tags", "endpoints",
                   "numerical_severity", "reporter", "last_reviewed",
                   "jira_creation", "jira_change", "files"]

    def filter_mitigation_available(self, queryset, name, value):
        if value:
            return queryset.exclude(mitigation__isnull=True).exclude(mitigation__exact="")
        return queryset.filter(Q(mitigation__isnull=True) | Q(mitigation__exact=""))

    def manage_kwargs(self, kwargs):
        self.prod_type = None
        self.product = None
        self.engagement = None
        self.test = None
        if "prod_type" in kwargs:
            self.prod_type = kwargs.pop("prod_type")
        if "product" in kwargs:
            self.product = kwargs.pop("product")
        if "engagement" in kwargs:
            self.engagement = kwargs.pop("engagement")
        if "test" in kwargs:
            self.test = kwargs.pop("test")

    @property
    def qs(self):
        parent = super().qs
        return get_authorized_findings_for_queryset("view", parent)


class ReportFindingFilter(ReportFindingFilterHelper, FindingTagFilter):
    test__engagement__product = ModelMultipleChoiceFilter(
        queryset=Product.objects.none(), label=labels.ASSET_FILTERS_LABEL)
    test__engagement__product__prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.none(),
        label=labels.ORG_FILTERS_LABEL)
    test__engagement__product__lifecycle = MultipleChoiceFilter(choices=Product.LIFECYCLE_CHOICES, label=labels.ASSET_LIFECYCLE_LABEL)
    test__engagement = ModelMultipleChoiceFilter(queryset=Engagement.objects.none(), label="Engagement")
    duplicate_finding = ModelChoiceFilter(queryset=Finding.objects.filter(original_finding__isnull=False).distinct())

    def __init__(self, *args, **kwargs):
        self.manage_kwargs(kwargs)
        super().__init__(*args, **kwargs)

        # duplicate_finding queryset needs to restricted in line with permissions
        # and inline with report scope to avoid a dropdown with 100K entries
        duplicate_finding_query_set = self.form.fields["duplicate_finding"].queryset
        duplicate_finding_query_set = get_authorized_findings_for_queryset("view", duplicate_finding_query_set)

        if self.test:
            duplicate_finding_query_set = duplicate_finding_query_set.filter(test=self.test)
            del self.form.fields["test__tags"]
            del self.form.fields["test__engagement__tags"]
            del self.form.fields["test__engagement__product__tags"]
        if self.engagement:
            duplicate_finding_query_set = duplicate_finding_query_set.filter(test__engagement=self.engagement)
            del self.form.fields["test__engagement__tags"]
            del self.form.fields["test__engagement__product__tags"]
        elif self.product:
            duplicate_finding_query_set = duplicate_finding_query_set.filter(test__engagement__product=self.product)
            del self.form.fields["test__engagement__product"]
            del self.form.fields["test__engagement__product__tags"]
        elif self.prod_type:
            duplicate_finding_query_set = duplicate_finding_query_set.filter(test__engagement__product__prod_type=self.prod_type)
            del self.form.fields["test__engagement__product__prod_type"]

        self.form.fields["duplicate_finding"].queryset = duplicate_finding_query_set

        if "test__engagement__product__prod_type" in self.form.fields:
            self.form.fields[
                "test__engagement__product__prod_type"].queryset = get_authorized_product_types("view")
        if "test__engagement__product" in self.form.fields:
            self.form.fields[
                "test__engagement__product"].queryset = get_authorized_products("view")
        if "test__engagement" in self.form.fields:
            self.form.fields["test__engagement"].queryset = get_authorized_engagements("view")


class ReportFindingFilterWithoutObjectLookups(ReportFindingFilterHelper, FindingTagStringFilter):
    test__engagement__product__prod_type = NumberFilter(widget=HiddenInput())
    test__engagement__product = NumberFilter(widget=HiddenInput())
    test__engagement = NumberFilter(widget=HiddenInput())
    test = NumberFilter(widget=HiddenInput())
    endpoint = NumberFilter(widget=HiddenInput())
    reporter = CharFilter(
        field_name="reporter__username",
        lookup_expr="iexact",
        label="Reporter Username",
        help_text="Search for Reporter names that are an exact match")
    reporter_contains = CharFilter(
        field_name="reporter__username",
        lookup_expr="icontains",
        label="Reporter Username Contains",
        help_text="Search for Reporter names that contain a given pattern")
    reviewers = CharFilter(
        field_name="reviewers__username",
        lookup_expr="iexact",
        label="Reviewer Username",
        help_text="Search for Reviewer names that are an exact match")
    reviewers_contains = CharFilter(
        field_name="reviewers__username",
        lookup_expr="icontains",
        label="Reviewer Username Contains",
        help_text="Search for Reviewer usernames that contain a given pattern")
    last_reviewed_by = CharFilter(
        field_name="last_reviewed_by__username",
        lookup_expr="iexact",
        label="Last Reviewed By Username",
        help_text="Search for Last Reviewed By names that are an exact match")
    last_reviewed_by_contains = CharFilter(
        field_name="last_reviewed_by__username",
        lookup_expr="icontains",
        label="Last Reviewed By Username Contains",
        help_text="Search for Last Reviewed By usernames that contain a given pattern")
    review_requested_by = CharFilter(
        field_name="review_requested_by__username",
        lookup_expr="iexact",
        label="Review Requested By Username",
        help_text="Search for Review Requested By names that are an exact match")
    review_requested_by_contains = CharFilter(
        field_name="review_requested_by__username",
        lookup_expr="icontains",
        label="Review Requested By Username Contains",
        help_text="Search for Review Requested By usernames that contain a given pattern")
    mitigated_by = CharFilter(
        field_name="mitigated_by__username",
        lookup_expr="iexact",
        label="Mitigator Username",
        help_text="Search for Mitigator names that are an exact match")
    mitigated_by_contains = CharFilter(
        field_name="mitigated_by__username",
        lookup_expr="icontains",
        label="Mitigator Username Contains",
        help_text="Search for Mitigator usernames that contain a given pattern")
    defect_review_requested_by = CharFilter(
        field_name="defect_review_requested_by__username",
        lookup_expr="iexact",
        label="Requester of Defect Review Username",
        help_text="Search for Requester of Defect Review names that are an exact match")
    defect_review_requested_by_contains = CharFilter(
        field_name="defect_review_requested_by__username",
        lookup_expr="icontains",
        label="Requester of Defect Review Username Contains",
        help_text="Search for Requester of Defect Review usernames that contain a given pattern")
    test__engagement__product__prod_type__name = CharFilter(
        field_name="test__engagement__product__prod_type__name",
        lookup_expr="iexact",
        label=labels.ORG_FILTERS_NAME_LABEL,
        help_text=labels.ORG_FILTERS_NAME_HELP)
    test__engagement__product__prod_type__name_contains = CharFilter(
        field_name="test__engagement__product__prod_type__name",
        lookup_expr="icontains",
        label=labels.ORG_FILTERS_NAME_CONTAINS_LABEL,
        help_text=labels.ORG_FILTERS_NAME_CONTAINS_HELP)
    test__engagement__product__name = CharFilter(
        field_name="test__engagement__product__name",
        lookup_expr="iexact",
        label=labels.ASSET_FILTERS_NAME_LABEL,
        help_text=labels.ASSET_FILTERS_NAME_HELP)
    test__engagement__product__name_contains = CharFilter(
        field_name="test__engagement__product__name",
        lookup_expr="icontains",
        label=labels.ASSET_FILTERS_NAME_CONTAINS_LABEL,
        help_text=labels.ASSET_FILTERS_NAME_CONTAINS_HELP)
    test__engagement__name = CharFilter(
        field_name="test__engagement__name",
        lookup_expr="iexact",
        label="Engagement Name",
        help_text="Search for Engagement names that are an exact match")
    test__engagement__name_contains = CharFilter(
        field_name="test__engagement__name",
        lookup_expr="icontains",
        label="Engagement name Contains",
        help_text="Search for Engagement names that contain a given pattern")
    test__name = CharFilter(
        field_name="test__title",
        lookup_expr="iexact",
        label="Test Name",
        help_text="Search for Test names that are an exact match")
    test__name_contains = CharFilter(
        field_name="test__title",
        lookup_expr="icontains",
        label="Test name Contains",
        help_text="Search for Test names that contain a given pattern")

    def __init__(self, *args, **kwargs):
        self.manage_kwargs(kwargs)
        super().__init__(*args, **kwargs)

        product_type_refs = [
            "test__engagement__product__prod_type__name",
            "test__engagement__product__prod_type__name_contains",
        ]
        product_refs = [
            "test__engagement__product__name",
            "test__engagement__product__name_contains",
            "test__engagement__product__tags",
            "test__engagement__product__tags_contains",
            "not_test__engagement__product__tags",
            "not_test__engagement__product__tags_contains",
        ]
        engagement_refs = [
            "test__engagement__name",
            "test__engagement__name_contains",
            "test__engagement__tags",
            "test__engagement__tags_contains",
            "not_test__engagement__tags",
            "not_test__engagement__tags_contains",
        ]
        test_refs = [
            "test__name",
            "test__name_contains",
            "test__tags",
            "test__tags_contains",
            "not_test__tags",
            "not_test__tags_contains",
        ]

        if self.test:
            self.delete_tags_from_form(product_type_refs)
            self.delete_tags_from_form(product_refs)
            self.delete_tags_from_form(engagement_refs)
            self.delete_tags_from_form(test_refs)
        elif self.engagement:
            self.delete_tags_from_form(product_type_refs)
            self.delete_tags_from_form(product_refs)
            self.delete_tags_from_form(engagement_refs)
        elif self.product:
            self.delete_tags_from_form(product_type_refs)
            self.delete_tags_from_form(product_refs)
        elif self.prod_type:
            self.delete_tags_from_form(product_type_refs)
