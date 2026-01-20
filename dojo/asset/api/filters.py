from django_filters import BooleanFilter, CharFilter, NumberFilter, OrderingFilter
from django_filters.rest_framework import FilterSet
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field

from dojo.filters import (
    CharFieldFilterANDExpression,
    CharFieldInFilter,
    DateRangeFilter,
    DojoFilter,
    MultipleChoiceFilter,
    NumberInFilter,
    ProductSLAFilter,
)
from dojo.labels import get_labels
from dojo.models import (
    Product,
    Product_API_Scan_Configuration,
    Product_Group,
    Product_Member,
)

labels = get_labels()


class AssetAPIScanConfigurationFilterSet(FilterSet):
    asset = NumberFilter(field_name="product")

    class Meta:
        model = Product_API_Scan_Configuration
        fields = ("id", "tool_configuration", "service_key_1", "service_key_2", "service_key_3")


class ApiAssetFilter(DojoFilter):
    # BooleanFilter
    external_audience = BooleanFilter(field_name="external_audience")
    internet_accessible = BooleanFilter(field_name="internet_accessible")
    # CharFilter
    name = CharFilter(lookup_expr="icontains")
    name_exact = CharFilter(field_name="name", lookup_expr="iexact")
    description = CharFilter(lookup_expr="icontains")
    business_criticality = MultipleChoiceFilter(choices=Product.BUSINESS_CRITICALITY_CHOICES)
    platform = MultipleChoiceFilter(choices=Product.PLATFORM_CHOICES)
    lifecycle = MultipleChoiceFilter(choices=Product.LIFECYCLE_CHOICES)
    origin = MultipleChoiceFilter(choices=Product.ORIGIN_CHOICES)
    # NumberInFilter
    id = NumberInFilter(field_name="id", lookup_expr="in")
    asset_manager = NumberInFilter(field_name="product_manager", lookup_expr="in")
    technical_contact = NumberInFilter(field_name="technical_contact", lookup_expr="in")
    team_manager = NumberInFilter(field_name="team_manager", lookup_expr="in")
    organization = NumberInFilter(field_name="prod_type", lookup_expr="in")
    tid = NumberInFilter(field_name="tid", lookup_expr="in")
    asset_numeric_grade = NumberInFilter(field_name="prod_numeric_grade", lookup_expr="in")
    user_records = NumberInFilter(field_name="user_records", lookup_expr="in")
    regulations = NumberInFilter(field_name="regulations", lookup_expr="in")

    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Tag name contains")
    tags = CharFieldInFilter(
        field_name="tags__name",
        lookup_expr="in",
        help_text="Comma separated list of exact tags (uses OR for multiple values)")
    tags__and = CharFieldFilterANDExpression(
        field_name="tags__name",
        help_text="Comma separated list of exact tags to match with an AND expression")
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Not Tag name contains", exclude="True")
    not_tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                                 help_text=labels.ASSET_FILTERS_CSV_TAGS_NOT_HELP, exclude="True")
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")
    outside_of_sla = extend_schema_field(OpenApiTypes.NUMBER)(ProductSLAFilter())

    # DateRangeFilter
    created = DateRangeFilter()
    updated = DateRangeFilter()
    # NumberFilter
    revenue = NumberFilter()

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("id", "id"),
            ("tid", "tid"),
            ("name", "name"),
            ("created", "created"),
            ("prod_numeric_grade", "asset_numeric_grade"),
            ("business_criticality", "business_criticality"),
            ("platform", "platform"),
            ("lifecycle", "lifecycle"),
            ("origin", "origin"),
            ("revenue", "revenue"),
            ("external_audience", "external_audience"),
            ("internet_accessible", "internet_accessible"),
            ("product_manager", "asset_manager"),
            ("product_manager__first_name", "asset_manager__first_name"),
            ("product_manager__last_name", "asset_manager__last_name"),
            ("technical_contact", "technical_contact"),
            ("technical_contact__first_name", "technical_contact__first_name"),
            ("technical_contact__last_name", "technical_contact__last_name"),
            ("team_manager", "team_manager"),
            ("team_manager__first_name", "team_manager__first_name"),
            ("team_manager__last_name", "team_manager__last_name"),
            ("prod_type", "organization"),
            ("prod_type__name", "organization__name"),
            ("updated", "updated"),
            ("user_records", "user_records"),
        ),
    )


class AssetMemberFilterSet(FilterSet):
    asset_id = NumberFilter(field_name="product_id")

    class Meta:
        model = Product_Member
        fields = ("id", "user_id")


class AssetGroupFilterSet(FilterSet):
    asset_id = NumberFilter(field_name="product_id")

    class Meta:
        model = Product_Group
        fields = ("id", "group_id")
