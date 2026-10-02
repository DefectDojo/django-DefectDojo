from django.forms import HiddenInput
from django_filters import (
    CharFilter,
    FilterSet,
    ModelMultipleChoiceFilter,
    NumberFilter,
    OrderingFilter,
)

from dojo.endpoint.models import Endpoint
from dojo.endpoint.queries import get_authorized_endpoints_for_queryset
from dojo.filters import DojoFilter
from dojo.labels import get_labels
from dojo.models import Engagement, Finding, Product, Test
from dojo.product.queries import get_authorized_products

labels = get_labels()


class EndpointFilterHelper(FilterSet):
    protocol = CharFilter(lookup_expr="icontains")
    userinfo = CharFilter(lookup_expr="icontains")
    host = CharFilter(lookup_expr="icontains")
    port = NumberFilter()
    path = CharFilter(lookup_expr="icontains")
    query = CharFilter(lookup_expr="icontains")
    fragment = CharFilter(lookup_expr="icontains")
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Tag name contains")
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)
    has_tags = CharFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")
    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("product", "product"),
            ("host", "host"),
            ("id", "id"),
            ("active_finding_count", "active_finding_count"),
        ),
        field_labels={
            "active_finding_count": "Active Findings Count",
        },
    )


class EndpointFilter(EndpointFilterHelper, DojoFilter):
    product = ModelMultipleChoiceFilter(
        queryset=Product.objects.none(),
        label=labels.ASSET_FILTERS_LABEL)
    tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        label="Endpoint Tags",
        queryset=Endpoint.tags.tag_model.objects.all().order_by("name"))
    findings__tags = ModelMultipleChoiceFilter(
        field_name="findings__tags__name",
        to_field_name="name",
        label="Finding Tags",
        queryset=Finding.tags.tag_model.objects.all().order_by("name"))
    findings__test__tags = ModelMultipleChoiceFilter(
        field_name="findings__test__tags__name",
        to_field_name="name",
        label="Test Tags",
        queryset=Test.tags.tag_model.objects.all().order_by("name"))
    findings__test__engagement__tags = ModelMultipleChoiceFilter(
        field_name="findings__test__engagement__tags__name",
        to_field_name="name",
        label="Engagement Tags",
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"))
    findings__test__engagement__product__tags = ModelMultipleChoiceFilter(
        field_name="findings__test__engagement__product__tags__name",
        to_field_name="name",
        label=labels.ASSET_FILTERS_TAGS_ASSET_LABEL,
        queryset=Product.tags.tag_model.objects.all().order_by("name"))
    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        label="Not Endpoint Tags",
        exclude=True,
        queryset=Endpoint.tags.tag_model.objects.all().order_by("name"))
    not_findings__tags = ModelMultipleChoiceFilter(
        field_name="findings__tags__name",
        to_field_name="name",
        label="Not Finding Tags",
        exclude=True,
        queryset=Finding.tags.tag_model.objects.all().order_by("name"))
    not_findings__test__tags = ModelMultipleChoiceFilter(
        field_name="findings__test__tags__name",
        to_field_name="name",
        label="Not Test Tags",
        exclude=True,
        queryset=Test.tags.tag_model.objects.all().order_by("name"))
    not_findings__test__engagement__tags = ModelMultipleChoiceFilter(
        field_name="findings__test__engagement__tags__name",
        to_field_name="name",
        label="Not Engagement Tags",
        exclude=True,
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"))
    not_findings__test__engagement__product__tags = ModelMultipleChoiceFilter(
        field_name="findings__test__engagement__product__tags__name",
        to_field_name="name",
        label=labels.ASSET_FILTERS_NOT_TAGS_ASSET_LABEL,
        exclude=True,
        queryset=Product.tags.tag_model.objects.all().order_by("name"))

    def __init__(self, *args, **kwargs):
        self.user = None
        if "user" in kwargs:
            self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)
        self.form.fields["product"].queryset = get_authorized_products("view")

    @property
    def qs(self):
        parent = super().qs
        return get_authorized_endpoints_for_queryset("view", parent)

    class Meta:
        model = Endpoint
        exclude = ["findings", "inherited_tags"]


class EndpointFilterWithoutObjectLookups(EndpointFilterHelper):
    product = NumberFilter(widget=HiddenInput())
    product__name = CharFilter(
        field_name="product__name",
        lookup_expr="iexact",
        label=labels.ASSET_FILTERS_NAME_LABEL,
        help_text=labels.ASSET_FILTERS_NAME_HELP)
    product__name_contains = CharFilter(
        field_name="product__name",
        lookup_expr="icontains",
        label=labels.ASSET_FILTERS_NAME_CONTAINS_LABEL,
        help_text=labels.ASSET_FILTERS_NAME_CONTAINS_HELP)

    tags_contains = CharFilter(
        label="Endpoint Tag Contains",
        field_name="tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Endpoint that contain a given pattern")
    tags = CharFilter(
        label="Endpoint Tag",
        field_name="tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Endpoint that are an exact match")
    findings__tags_contains = CharFilter(
        label="Finding Tag Contains",
        field_name="findings__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    findings__tags = CharFilter(
        label="Finding Tag",
        field_name="findings__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")
    findings__test__tags_contains = CharFilter(
        label="Test Tag Contains",
        field_name="findings__test__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    findings__test__tags = CharFilter(
        label="Test Tag",
        field_name="findings__test__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")
    findings__test__engagement__tags_contains = CharFilter(
        label="Engagement Tag Contains",
        field_name="findings__test__engagement__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern")
    findings__test__engagement__tags = CharFilter(
        label="Engagement Tag",
        field_name="findings__test__engagement__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match")
    findings__test__engagement__product__tags_contains = CharFilter(
        label=labels.ASSET_FILTERS_TAG_ASSET_CONTAINS_LABEL,
        field_name="findings__test__engagement__product__tags__name",
        lookup_expr="icontains",
        help_text=labels.ASSET_FILTERS_TAG_ASSET_CONTAINS_HELP)
    findings__test__engagement__product__tags = CharFilter(
        label=labels.ASSET_FILTERS_TAG_ASSET_LABEL,
        field_name="findings__test__engagement__product__tags__name",
        lookup_expr="iexact",
        help_text=labels.ASSET_FILTERS_TAG_ASSET_HELP)

    not_tags_contains = CharFilter(
        label="Endpoint Tag Does Not Contain",
        field_name="tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Endpoint that contain a given pattern, and exclude them",
        exclude=True)
    not_tags = CharFilter(
        label="Not Endpoint Tag",
        field_name="tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Endpoint that are an exact match, and exclude them",
        exclude=True)
    not_findings__tags_contains = CharFilter(
        label="Finding Tag Does Not Contain",
        field_name="findings__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Finding that contain a given pattern, and exclude them",
        exclude=True)
    not_findings__tags = CharFilter(
        label="Not Finding Tag",
        field_name="findings__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Finding that are an exact match, and exclude them",
        exclude=True)
    not_findings__test__tags_contains = CharFilter(
        label="Test Tag Does Not Contain",
        field_name="findings__test__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Test that contain a given pattern, and exclude them",
        exclude=True)
    not_findings__test__tags = CharFilter(
        label="Not Test Tag",
        field_name="findings__test__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Test that are an exact match, and exclude them",
        exclude=True)
    not_findings__test__engagement__tags_contains = CharFilter(
        label="Engagement Tag Does Not Contain",
        field_name="findings__test__engagement__tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Engagement that contain a given pattern, and exclude them",
        exclude=True)
    not_findings__test__engagement__tags = CharFilter(
        label="Not Engagement Tag",
        field_name="findings__test__engagement__tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Engagement that are an exact match, and exclude them",
        exclude=True)
    not_findings__test__engagement__product__tags_contains = CharFilter(
        label=labels.ASSET_FILTERS_TAG_NOT_CONTAIN_LABEL,
        field_name="findings__test__engagement__product__tags__name",
        lookup_expr="icontains",
        help_text=labels.ASSET_FILTERS_TAG_NOT_CONTAIN_HELP,
        exclude=True)
    not_findings__test__engagement__product__tags = CharFilter(
        label=labels.ASSET_FILTERS_TAG_NOT_LABEL,
        field_name="findings__test__engagement__product__tags__name",
        lookup_expr="iexact",
        help_text=labels.ASSET_FILTERS_TAG_NOT_HELP,
        exclude=True)

    def __init__(self, *args, **kwargs):
        self.user = None
        if "user" in kwargs:
            self.user = kwargs.pop("user")
        super().__init__(*args, **kwargs)

    @property
    def qs(self):
        parent = super().qs
        return get_authorized_endpoints_for_queryset("view", parent)

    class Meta:
        model = Endpoint
        exclude = ["findings", "inherited_tags", "product"]
