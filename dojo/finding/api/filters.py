from datetime import timedelta

from django.db.models import Exists, OuterRef, Q
from django_filters import (
    BooleanFilter,
    CharFilter,
    DateFilter,
    DateTimeFilter,
    OrderingFilter,
)
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field

from dojo.filters import (
    CharFieldFilterANDExpression,
    CharFieldInFilter,
    DateRangeFilter,
    DojoFilter,
    ExistsRiskAcceptanceFilter,
    FindingSLAFilter,
    MultivaluedOrderingFilter,
    NumberInFilter,
    PercentageRangeFilter,
    custom_filter,
    custom_vulnerability_id_filter,
    labels,
)
from dojo.models import Finding, Finding_Template


class ApiFindingFilter(DojoFilter):
    # BooleanFilter
    active = BooleanFilter(field_name="active")
    duplicate = BooleanFilter(field_name="duplicate")
    dynamic_finding = BooleanFilter(field_name="dynamic_finding")
    false_p = BooleanFilter(field_name="false_p")
    is_mitigated = BooleanFilter(field_name="is_mitigated")
    out_of_scope = BooleanFilter(field_name="out_of_scope")
    static_finding = BooleanFilter(field_name="static_finding")
    under_defect_review = BooleanFilter(field_name="under_defect_review")
    under_review = BooleanFilter(field_name="under_review")
    verified = BooleanFilter(field_name="verified")
    has_jira = BooleanFilter(field_name="jira_issue", lookup_expr="isnull", exclude=True)
    fix_available = BooleanFilter(field_name="fix_available")
    mitigation_available = BooleanFilter(method="filter_mitigation_available", label="Mitigation Available")
    # CharFilter
    component_version = CharFilter(lookup_expr="icontains")
    component_name = CharFilter(lookup_expr="icontains")
    vulnerability_id = CharFilter(method=custom_vulnerability_id_filter)
    description = CharFilter(lookup_expr="icontains")
    file_path = CharFilter(lookup_expr="icontains")
    hash_code = CharFilter(lookup_expr="icontains")
    impact = CharFilter(lookup_expr="icontains")
    mitigation = CharFilter(lookup_expr="icontains")
    numerical_severity = CharFilter(method=custom_filter, field_name="numerical_severity")
    param = CharFilter(lookup_expr="icontains")
    payload = CharFilter(lookup_expr="icontains")
    references = CharFilter(lookup_expr="icontains")
    severity = CharFilter(method=custom_filter, field_name="severity")
    severity_justification = CharFilter(lookup_expr="icontains")
    steps_to_reproduce = CharFilter(lookup_expr="icontains")
    unique_id_from_tool = CharFilter(lookup_expr="icontains")
    title = CharFilter(lookup_expr="icontains")
    exact_title = CharFilter(field_name="title", lookup_expr="iexact", help_text="Finding title exact match (case-insensitive)")
    product_name = CharFilter(lookup_expr="engagement__product__name__iexact", field_name="test", label=labels.ASSET_FILTERS_NAME_EXACT_LABEL)
    product_name_contains = CharFilter(lookup_expr="engagement__product__name__icontains", field_name="test", label=labels.ASSET_FILTERS_NAME_CONTAINS_LABEL)
    product_lifecycle = CharFilter(method=custom_filter, lookup_expr="engagement__product__lifecycle",
                                   field_name="test__engagement__product__lifecycle", label=labels.ASSET_FILTERS_CSV_LIFECYCLES_LABEL)
    # DateRangeFilter
    created = DateRangeFilter()
    date = DateRangeFilter()
    discovered_on = DateFilter(field_name="date", lookup_expr="exact")
    discovered_before = DateFilter(field_name="date", lookup_expr="lt")
    discovered_after = DateFilter(field_name="date", lookup_expr="gt")
    jira_creation = DateRangeFilter(field_name="jira_issue__jira_creation")
    jira_change = DateRangeFilter(field_name="jira_issue__jira_change")
    last_reviewed = DateRangeFilter()
    mitigated = DateRangeFilter()
    mitigated_on = DateTimeFilter(field_name="mitigated", lookup_expr="exact", method="filter_mitigated_on")
    mitigated_before = DateTimeFilter(field_name="mitigated", lookup_expr="lt")
    mitigated_after = DateTimeFilter(field_name="mitigated", lookup_expr="gt", label="Mitigated After", method="filter_mitigated_after")
    # NumberInFilter
    cwe = NumberInFilter(field_name="cwe", lookup_expr="in")
    defect_review_requested_by = NumberInFilter(field_name="defect_review_requested_by", lookup_expr="in")
    endpoints = NumberInFilter(method="filter_endpoints")
    epss_score = PercentageRangeFilter(
        field_name="epss_score",
        label="EPSS score range",
        help_text=(
            "The range of EPSS score percentages to filter on; the min input is a lower bound, "
            "the max is an upper bound. Leaving one empty will skip that bound (e.g., leaving "
            "the min bound input empty will filter only on the max bound -- filtering on "
            '"less than or equal"). Leading 0 required.'
        ))
    epss_percentile = PercentageRangeFilter(
        field_name="epss_percentile",
        label="EPSS percentile range",
        help_text=(
            "The range of EPSS percentiles to filter on; the min input is a lower bound, the max "
            "is an upper bound. Leaving one empty will skip that bound (e.g., leaving the min bound "
            'input empty will filter only on the max bound -- filtering on "less than or equal"). Leading 0 required.'
        ))
    found_by = NumberInFilter(method="filter_found_by")
    id = NumberInFilter(field_name="id", lookup_expr="in")
    last_reviewed_by = NumberInFilter(field_name="last_reviewed_by", lookup_expr="in")
    mitigated_by = NumberInFilter(field_name="mitigated_by", lookup_expr="in")
    nb_occurences = NumberInFilter(field_name="nb_occurences", lookup_expr="in")
    reporter = NumberInFilter(field_name="reporter", lookup_expr="in")
    scanner_confidence = NumberInFilter(field_name="scanner_confidence", lookup_expr="in")
    review_requested_by = NumberInFilter(field_name="review_requested_by", lookup_expr="in")
    reviewers = NumberInFilter(method="filter_reviewers")
    sast_source_line = NumberInFilter(field_name="sast_source_line", lookup_expr="in")
    sonarqube_issue = NumberInFilter(field_name="sonarqube_issue", lookup_expr="in")
    test__test_type = NumberInFilter(field_name="test__test_type", lookup_expr="in", label="Test Type")
    test__engagement = NumberInFilter(field_name="test__engagement", lookup_expr="in")
    test__engagement__product = NumberInFilter(field_name="test__engagement__product", lookup_expr="in")
    test__engagement__product__prod_type = NumberInFilter(field_name="test__engagement__product__prod_type", lookup_expr="in")
    finding_group = NumberInFilter(method="filter_finding_group")

    # ExistsRiskAcceptanceFilter
    risk_acceptance = extend_schema_field(OpenApiTypes.NUMBER)(ExistsRiskAcceptanceFilter())

    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Tag name contains")
    tags = CharFieldInFilter(
        field_name="tags__name",
        lookup_expr="in",
        help_text="Comma separated list of exact tags (uses OR for multiple values)")
    tags__and = CharFieldFilterANDExpression(
        field_name="tags__name",
        help_text="Comma separated list of exact tags to match with an AND expression")
    test__tags = CharFieldInFilter(
        field_name="test__tags__name",
        lookup_expr="in",
        help_text="Comma separated list of exact tags present on test (uses OR for multiple values)")
    test__tags__and = CharFieldFilterANDExpression(
        field_name="test__tags__name",
        help_text="Comma separated list of exact tags to match with an AND expression present on test")
    test__engagement__tags = CharFieldInFilter(
        field_name="test__engagement__tags__name",
        lookup_expr="in",
        help_text="Comma separated list of exact tags present on engagement (uses OR for multiple values)")
    test__engagement__tags__and = CharFieldFilterANDExpression(
        field_name="test__engagement__tags__name",
        help_text="Comma separated list of exact tags to match with an AND expression present on engagement")
    test__engagement__product__tags = CharFieldInFilter(
        field_name="test__engagement__product__tags__name",
        lookup_expr="in",
        help_text=labels.ASSET_FILTERS_CSV_TAGS_OR_HELP)
    test__engagement__product__tags__and = CharFieldFilterANDExpression(
        field_name="test__engagement__product__tags__name",
        help_text=labels.ASSET_FILTERS_CSV_TAGS_AND_HELP)
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Not Tag name contains", exclude="True")
    not_tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                                 help_text="Comma separated list of exact tags not present on model", exclude="True")
    not_test__tags = CharFieldInFilter(field_name="test__tags__name", lookup_expr="in", exclude="True", help_text="Comma separated list of exact tags present on test")
    not_test__engagement__tags = CharFieldInFilter(field_name="test__engagement__tags__name", lookup_expr="in",
                                                   help_text="Comma separated list of exact tags not present on engagement",
                                                   exclude="True")
    not_test__engagement__product__tags = CharFieldInFilter(
        field_name="test__engagement__product__tags__name",
        lookup_expr="in",
        help_text=labels.ASSET_FILTERS_CSV_TAGS_NOT_HELP,
        exclude="True")
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")
    outside_of_sla = extend_schema_field(OpenApiTypes.NUMBER)(FindingSLAFilter())

    # found_by / reviewers are to-many; aggregate them on sort so ordering does not re-multiply rows
    # now that the blanket .distinct() is gone (see MultivaluedOrderingFilter / get_queryset).
    o = MultivaluedOrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("active", "active"),
            ("component_name", "component_name"),
            ("component_version", "component_version"),
            ("created", "created"),
            ("last_status_update", "last_status_update"),
            ("last_reviewed", "last_reviewed"),
            ("cwe", "cwe"),
            ("date", "date"),
            ("duplicate", "duplicate"),
            ("dynamic_finding", "dynamic_finding"),
            ("false_p", "false_p"),
            ("found_by", "found_by"),
            ("id", "id"),
            ("is_mitigated", "is_mitigated"),
            ("numerical_severity", "numerical_severity"),
            ("out_of_scope", "out_of_scope"),
            ("planned_remediation_date", "planned_remediation_date"),
            ("severity", "severity"),
            ("sla_expiration_date", "sla_expiration_date"),
            ("reviewers", "reviewers"),
            ("static_finding", "static_finding"),
            ("test__engagement__product__name", "test__engagement__product__name"),
            ("title", "title"),
            ("under_defect_review", "under_defect_review"),
            ("under_review", "under_review"),
            ("verified", "verified"),
        ),
        multivalued_fields={"found_by", "reviewers"},
    )

    class Meta:
        model = Finding
        exclude = ["url", "thread_id", "notes", "files",
                   "line", "cve"]

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

    @staticmethod
    def _has(**lookup):
        # endpoints / found_by / reviewers / finding_group are to-many relations: a plain JOIN-based
        # lookup__in filter emits one row per related match and multiplies the finding row. Exists()
        # keeps the outer row count correct, so FindingViewSet.get_queryset() can drop its blanket
        # .distinct() without these filters producing duplicates.
        return Exists(Finding.objects.filter(pk=OuterRef("pk"), **lookup))

    def filter_endpoints(self, queryset, _name, value):
        return queryset.filter(self._has(endpoints__id__in=value)) if value else queryset

    def filter_found_by(self, queryset, _name, value):
        return queryset.filter(self._has(found_by__in=value)) if value else queryset

    def filter_reviewers(self, queryset, _name, value):
        return queryset.filter(self._has(reviewers__in=value)) if value else queryset

    def filter_finding_group(self, queryset, _name, value):
        # finding_group is the reverse side of Finding_Group.findings (M2M, no related_name), so the
        # reverse query name is finding_group; dedupe via Exists() like the other to-many filters.
        return queryset.filter(self._has(finding_group__id__in=value)) if value else queryset


class ApiTemplateFindingFilter(DojoFilter):
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Tag name contains")
    tags = CharFieldInFilter(
        field_name="tags__name",
        lookup_expr="in",
        help_text="Comma separated list of exact tags (uses OR for multiple values)")
    tags__and = CharFieldFilterANDExpression(
        field_name="tags__name",
        help_text="Comma separated list of exact tags to match with an AND expression")
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Not Tag name contains", exclude="True")
    not_tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                                 help_text="Comma separated list of exact tags not present on model", exclude="True")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("title", "title"),
            ("cwe", "cwe"),
        ),
    )

    class Meta:
        model = Finding_Template
        fields = ["id", "title", "cwe", "severity", "description",
                     "mitigation"]
