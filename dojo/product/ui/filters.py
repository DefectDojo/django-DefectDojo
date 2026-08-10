from django.conf import settings
from django.forms import HiddenInput
from django_filters import (
    BooleanFilter,
    CharFilter,
    FilterSet,
    ModelMultipleChoiceFilter,
    MultipleChoiceFilter,
    NumberFilter,
    OrderingFilter,
)

from dojo.filters import (
    DojoFilter,
    ProductSLAFilter,
    filter_endpoints_base,
    filter_endpoints_host_base,
)
from dojo.labels import get_labels
from dojo.location.status import ProductLocationStatus
from dojo.models import Product, Product_Type
from dojo.product.queries import get_authorized_products
from dojo.product_type.queries import get_authorized_product_types

labels = get_labels()


class ProductComponentFilter(DojoFilter):
    component_name = CharFilter(lookup_expr="icontains", label="Module Name")
    component_version = CharFilter(lookup_expr="icontains", label="Module Version")

    o = OrderingFilter(
        fields=(
            ("component_name", "component_name"),
            ("component_version", "component_version"),
            ("active", "active"),
            ("duplicate", "duplicate"),
            ("total", "total"),
        ),
        field_labels={
            "component_name": "Component Name",
            "component_version": "Component Version",
            "active": "Active",
            "duplicate": "Duplicate",
            "total": "Total",
        },
    )


class ComponentFilterWithoutObjectLookups(ProductComponentFilter):
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


class ComponentFilter(ProductComponentFilter):
    test__engagement__product__prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.none(),
        label=labels.ORG_FILTERS_LABEL)
    test__engagement__product = ModelMultipleChoiceFilter(
        queryset=Product.objects.none(),
        label=labels.ASSET_FILTERS_LABEL)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.form.fields[
            "test__engagement__product__prod_type"].queryset = get_authorized_product_types("view")
        self.form.fields[
            "test__engagement__product"].queryset = get_authorized_products("view")


class ProductFilterHelper(FilterSet):
    name = CharFilter(lookup_expr="icontains", label=labels.ASSET_FILTERS_NAME_LABEL)
    name_exact = CharFilter(field_name="name", lookup_expr="iexact", label=labels.ASSET_FILTERS_NAME_EXACT_LABEL)
    business_criticality = MultipleChoiceFilter(choices=Product.BUSINESS_CRITICALITY_CHOICES, null_label="Empty")
    platform = MultipleChoiceFilter(choices=Product.PLATFORM_CHOICES, null_label="Empty")
    lifecycle = MultipleChoiceFilter(choices=Product.LIFECYCLE_CHOICES, null_label="Empty")
    origin = MultipleChoiceFilter(choices=Product.ORIGIN_CHOICES, null_label="Empty")
    external_audience = BooleanFilter(field_name="external_audience")
    internet_accessible = BooleanFilter(field_name="internet_accessible")
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Tag contains")
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)
    outside_of_sla = ProductSLAFilter(label="Outside of SLA")
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")
    if settings.V3_FEATURE_LOCATIONS:
        location_status = MultipleChoiceFilter(
            field_name="locations__status",
            choices=ProductLocationStatus.choices,
            help_text="Status of the Location from the Products relationship",
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

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("name", "name"),
            ("name_exact", "name_exact"),
            ("prod_type__name", "prod_type__name"),
            ("business_criticality", "business_criticality"),
            ("platform", "platform"),
            ("lifecycle", "lifecycle"),
            ("origin", "origin"),
            ("external_audience", "external_audience"),
            ("internet_accessible", "internet_accessible"),
            ("findings_count", "findings_count"),
        ),
        field_labels={
            "name": labels.ASSET_FILTERS_NAME_LABEL,
            "name_exact": labels.ASSET_FILTERS_NAME_EXACT_LABEL,
            "prod_type__name": labels.ORG_FILTERS_LABEL,
            "business_criticality": "Business Criticality",
            "platform": "Platform ",
            "lifecycle": "Lifecycle ",
            "origin": "Origin ",
            "external_audience": "External Audience ",
            "internet_accessible": "Internet Accessible ",
            "findings_count": "Findings Count ",
        },
    )


class ProductFilter(ProductFilterHelper, DojoFilter):
    prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.none(),
        label=labels.ORG_FILTERS_LABEL)
    tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        queryset=Product.tags.tag_model.objects.all().order_by("name"))
    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        exclude=True,
        queryset=Product.tags.tag_model.objects.all().order_by("name"))

    def __init__(self, *args, **kwargs):
        self.user = None
        if "user" in kwargs:
            self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)
        self.form.fields["prod_type"].queryset = get_authorized_product_types("view")
        self.form.fields["tags"].help_text = labels.ASSET_FILTERS_TAGS_HELP
        self.form.fields["not_tags"].help_text = labels.ASSET_FILTERS_NOT_TAGS_HELP

    class Meta:
        model = Product
        fields = [
            "name", "name_exact", "prod_type", "business_criticality",
            "platform", "lifecycle", "origin", "external_audience",
            "internet_accessible", "tags",
        ]


class ProductFilterWithoutObjectLookups(ProductFilterHelper):
    prod_type__name = CharFilter(
        field_name="prod_type__name",
        lookup_expr="iexact",
        label=labels.ORG_FILTERS_NAME_LABEL,
        help_text=labels.ORG_FILTERS_NAME_HELP)
    prod_type__name_contains = CharFilter(
        field_name="prod_type__name",
        lookup_expr="icontains",
        label=labels.ORG_FILTERS_NAME_CONTAINS_LABEL,
        help_text=labels.ORG_FILTERS_NAME_CONTAINS_HELP)

    def __init__(self, *args, **kwargs):
        kwargs.pop("user", None)
        super().__init__(*args, **kwargs)

    class Meta:
        model = Product
        fields = [
            "name", "name_exact", "business_criticality", "platform",
            "lifecycle", "origin", "external_audience", "internet_accessible",
        ]
