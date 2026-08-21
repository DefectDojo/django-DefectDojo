from django.conf import settings
from django_filters import (
    BooleanFilter,
    CharFilter,
    FilterSet,
    ModelChoiceFilter,
    ModelMultipleChoiceFilter,
    MultipleChoiceFilter,
    OrderingFilter,
)

from dojo.filters import DateRangeFilter, DojoFilter
from dojo.labels import get_labels
from dojo.models import (
    ENGAGEMENT_STATUS_CHOICES,
    Dojo_User,
    Engagement,
    Product,
    Product_API_Scan_Configuration,
    Product_Type,
    Test,
    Test_Type,
)
from dojo.product_type.queries import get_authorized_product_types
from dojo.user.queries import get_authorized_users

labels = get_labels()


class EngagementDirectFilterHelper(FilterSet):
    name = CharFilter(lookup_expr="icontains", label="Engagement name contains")
    version = CharFilter(field_name="version", lookup_expr="icontains", label="Engagement version")
    test__version = CharFilter(field_name="test__version", lookup_expr="icontains", label="Test version")
    product__name = CharFilter(lookup_expr="icontains", label=labels.ASSET_FILTERS_NAME_CONTAINS_LABEL)
    status = MultipleChoiceFilter(choices=ENGAGEMENT_STATUS_CHOICES, label="Status")
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Tag name contains")
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")
    target_start = DateRangeFilter()
    target_end = DateRangeFilter()
    test__engagement__product__lifecycle = MultipleChoiceFilter(
        choices=Product.LIFECYCLE_CHOICES,
        label=labels.ASSET_LIFECYCLE_LABEL,
        null_label="Empty")
    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("target_start", "target_start"),
            ("name", "name"),
            ("product__name", "product__name"),
            ("product__prod_type__name", "product__prod_type__name"),
            ("lead__first_name", "lead__first_name"),
        ),
        field_labels={
            "target_start": "Start date",
            "name": "Engagement",
            "product__name": labels.ASSET_FILTERS_NAME_LABEL,
            "product__prod_type__name": labels.ORG_FILTERS_LABEL,
            "lead__first_name": "Lead",
        },
    )


class EngagementDirectFilter(EngagementDirectFilterHelper, DojoFilter):
    lead = ModelChoiceFilter(queryset=Dojo_User.objects.none(), label="Lead")
    product__prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.none(),
        label=labels.ORG_FILTERS_LABEL)
    tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"))
    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        exclude=True,
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.form.fields["product__prod_type"].queryset = get_authorized_product_types("view")
        self.form.fields["lead"].queryset = get_authorized_users("view") \
            .filter(engagement__lead__isnull=False).distinct()

    class Meta:
        model = Engagement
        fields = ["product__name", "product__prod_type"]


class EngagementDirectFilterWithoutObjectLookups(EngagementDirectFilterHelper):
    lead = CharFilter(
        field_name="lead__username",
        lookup_expr="iexact",
        label="Lead Username",
        help_text="Search for Lead username that are an exact match")
    lead_contains = CharFilter(
        field_name="lead__username",
        lookup_expr="icontains",
        label="Lead Username Contains",
        help_text="Search for Lead username that contain a given pattern")
    product__prod_type__name = CharFilter(
        field_name="product__prod_type__name",
        lookup_expr="iexact",
        label=labels.ORG_FILTERS_NAME_LABEL,
        help_text=labels.ORG_FILTERS_NAME_HELP)
    product__prod_type__name_contains = CharFilter(
        field_name="product__prod_type__name",
        lookup_expr="icontains",
        label=labels.ORG_FILTERS_NAME_CONTAINS_LABEL,
        help_text=labels.ORG_FILTERS_NAME_CONTAINS_HELP)

    class Meta:
        model = Engagement
        fields = ["product__name"]


class EngagementFilterHelper(FilterSet):
    name = CharFilter(lookup_expr="icontains", label=labels.ASSET_FILTERS_NAME_CONTAINS_LABEL)
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Tag name contains")
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")
    engagement__name = CharFilter(lookup_expr="icontains", label="Engagement name contains")
    engagement__version = CharFilter(field_name="engagement__version", lookup_expr="icontains", label="Engagement version")
    engagement__test__version = CharFilter(field_name="engagement__test__version", lookup_expr="icontains", label="Test version")
    engagement__product__lifecycle = MultipleChoiceFilter(
        choices=Product.LIFECYCLE_CHOICES,
        label=labels.ASSET_LIFECYCLE_LABEL,
        null_label="Empty")
    engagement__status = MultipleChoiceFilter(
        choices=ENGAGEMENT_STATUS_CHOICES,
        label="Status")
    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("name", "name"),
            ("prod_type__name", "prod_type__name"),
        ),
        field_labels={
            "name": labels.ASSET_FILTERS_NAME_LABEL,
            "prod_type__name": labels.ORG_FILTERS_LABEL,
        },
    )


class EngagementFilter(EngagementFilterHelper, DojoFilter):
    engagement__lead = ModelChoiceFilter(
        queryset=Dojo_User.objects.none(),
        label="Lead")
    prod_type = ModelMultipleChoiceFilter(
        queryset=Product_Type.objects.none(),
        label=labels.ORG_FILTERS_LABEL)
    tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"))
    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        exclude=True,
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.form.fields["prod_type"].queryset = get_authorized_product_types("view")
        self.form.fields["engagement__lead"].queryset = get_authorized_users("view") \
            .filter(engagement__lead__isnull=False).distinct()
        self.form.fields["tags"].help_text = labels.ASSET_FILTERS_TAGS_HELP
        self.form.fields["not_tags"].help_text = labels.ASSET_FILTERS_NOT_TAGS_HELP

    class Meta:
        model = Product
        fields = ["name", "prod_type"]


class ProductEngagementsFilter(DojoFilter):
    engagement__name = CharFilter(field_name="name", lookup_expr="icontains", label="Engagement name contains")
    engagement__lead = ModelChoiceFilter(field_name="lead", queryset=Dojo_User.objects.none(), label="Lead")
    engagement__version = CharFilter(field_name="version", lookup_expr="icontains", label="Engagement version")
    engagement__test__version = CharFilter(field_name="test__version", lookup_expr="icontains", label="Test version")
    engagement__status = MultipleChoiceFilter(field_name="status", choices=ENGAGEMENT_STATUS_CHOICES,
                                              label="Status")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.form.fields["engagement__lead"].queryset = get_authorized_users("view") \
            .filter(engagement__lead__isnull=False).distinct()

    class Meta:
        model = Engagement
        fields = []


class ProductEngagementsFilterWithoutObjectLookups(ProductEngagementsFilter):
    engagement__lead = CharFilter(
        field_name="lead__username",
        lookup_expr="iexact",
        label="Lead Username",
        help_text="Search for Lead username that are an exact match")


class EngagementFilterWithoutObjectLookups(EngagementFilterHelper):
    engagement__lead = CharFilter(
        field_name="engagement__lead__username",
        lookup_expr="iexact",
        label="Lead Username",
        help_text="Search for Lead username that are an exact match")
    engagement__lead_contains = CharFilter(
        field_name="engagement__lead__username",
        lookup_expr="icontains",
        label="Lead Username Contains",
        help_text="Search for Lead username that contain a given pattern")
    prod_type__name = CharFilter(
        field_name="prod_type__name",
        lookup_expr="iexact",
        label=labels.ORG_FILTERS_LABEL,
        help_text=labels.ORG_FILTERS_LABEL_HELP)
    prod_type__name_contains = CharFilter(
        field_name="prod_type__name",
        lookup_expr="icontains",
        label=labels.ORG_FILTERS_NAME_CONTAINS_LABEL,
        help_text=labels.ORG_FILTERS_NAME_CONTAINS_HELP)

    class Meta:
        model = Product
        fields = ["name"]


class ProductEngagementFilterHelper(FilterSet):
    version = CharFilter(lookup_expr="icontains", label="Engagement version")
    test__version = CharFilter(field_name="test__version", lookup_expr="icontains", label="Test version")
    name = CharFilter(lookup_expr="icontains")
    status = MultipleChoiceFilter(choices=ENGAGEMENT_STATUS_CHOICES, label="Status")
    target_start = DateRangeFilter()
    target_end = DateRangeFilter()
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Tag name contains")
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)
    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("name", "name"),
            ("version", "version"),
            ("target_start", "target_start"),
            ("target_end", "target_end"),
            ("status", "status"),
            ("lead", "lead"),
        ),
        field_labels={
            "name": "Engagement Name",
        },
    )

    class Meta:
        model = Product
        fields = ["name"]


class ProductEngagementFilter(ProductEngagementFilterHelper, DojoFilter):
    lead = ModelChoiceFilter(queryset=Dojo_User.objects.none(), label="Lead")
    tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"))
    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        exclude=True,
        queryset=Engagement.tags.tag_model.objects.all().order_by("name"))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.form.fields["lead"].queryset = get_authorized_users(
            "view").filter(engagement__lead__isnull=False).distinct()


class ProductEngagementFilterWithoutObjectLookups(ProductEngagementFilterHelper, DojoFilter):
    lead = CharFilter(
        field_name="lead__username",
        lookup_expr="iexact",
        label="Lead Username",
        help_text="Search for Lead username that are an exact match")
    lead_contains = CharFilter(
        field_name="lead__username",
        lookup_expr="icontains",
        label="Lead Username Contains",
        help_text="Search for Lead username that contain a given pattern")


class EngagementTestFilterHelper(FilterSet):
    version = CharFilter(lookup_expr="icontains", label="Version")
    if settings.TRACK_IMPORT_HISTORY:
        test_import__version = CharFilter(field_name="test_import__version", lookup_expr="icontains", label="Reimported Version")
    target_start = DateRangeFilter()
    target_end = DateRangeFilter()
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Tag name contains")
    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", label="Not tag name contains", exclude=True)
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")
    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("title", "title"),
            ("version", "version"),
            ("target_start", "target_start"),
            ("target_end", "target_end"),
            ("lead", "lead"),
            ("api_scan_configuration", "api_scan_configuration"),
        ),
        field_labels={
            "name": "Test Name",
        },
    )


class EngagementTestFilter(EngagementTestFilterHelper, DojoFilter):
    lead = ModelChoiceFilter(queryset=Dojo_User.objects.none(), label="Lead")
    api_scan_configuration = ModelChoiceFilter(
        queryset=Product_API_Scan_Configuration.objects.none(),
        label="API Scan Configuration")
    tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        queryset=Test.tags.tag_model.objects.all().order_by("name"))
    not_tags = ModelMultipleChoiceFilter(
        field_name="tags__name",
        to_field_name="name",
        exclude=True,
        queryset=Test.tags.tag_model.objects.all().order_by("name"))

    class Meta:
        model = Test
        fields = [
            "title", "test_type", "target_start",
            "target_end", "percent_complete",
            "version", "api_scan_configuration",
        ]

    def __init__(self, *args, **kwargs):
        self.engagement = kwargs.pop("engagement")
        super(DojoFilter, self).__init__(*args, **kwargs)
        self.form.fields["test_type"].queryset = Test_Type.objects.filter(test__engagement=self.engagement).distinct().order_by("name")
        self.form.fields["api_scan_configuration"].queryset = Product_API_Scan_Configuration.objects.filter(product=self.engagement.product).distinct()
        self.form.fields["lead"].queryset = get_authorized_users("view") \
            .filter(test__lead__isnull=False).distinct()


class EngagementTestFilterWithoutObjectLookups(EngagementTestFilterHelper):
    lead = CharFilter(
        field_name="lead__username",
        lookup_expr="iexact",
        label="Lead Username",
        help_text="Search for Lead username that are an exact match")
    lead_contains = CharFilter(
        field_name="lead__username",
        lookup_expr="icontains",
        label="Lead Username Contains",
        help_text="Search for Lead username that contain a given pattern")
    api_scan_configuration__tool_configuration__name = CharFilter(
        field_name="api_scan_configuration__tool_configuration__name",
        lookup_expr="iexact",
        label="API Scan Configuration Name",
        help_text="Search for Lead username that are an exact match")
    api_scan_configuration__tool_configuration__name_contains = CharFilter(
        field_name="api_scan_configuration__tool_configuration__name",
        lookup_expr="icontains",
        label="API Scan Configuration Name Contains",
        help_text="Search for Lead username that contain a given pattern")
    tags_contains = CharFilter(
        label="Test Tag Contains",
        field_name="tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Test that contain a given pattern")
    tags = CharFilter(
        label="Test Tag",
        field_name="tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Test that are an exact match")
    not_tags_contains = CharFilter(
        label="Test Tag Does Not Contain",
        field_name="tags__name",
        lookup_expr="icontains",
        help_text="Search for tags on a Test that contain a given pattern, and exclude them",
        exclude=True)
    not_tags = CharFilter(
        label="Not Test Tag",
        field_name="tags__name",
        lookup_expr="iexact",
        help_text="Search for tags on a Test that are an exact match, and exclude them",
        exclude=True)

    class Meta:
        model = Test
        fields = [
            "title", "test_type", "target_start",
            "target_end", "percent_complete", "version",
        ]

    def __init__(self, *args, **kwargs):
        self.engagement = kwargs.pop("engagement")
        super().__init__(*args, **kwargs)
        self.form.fields["test_type"].queryset = Test_Type.objects.filter(test__engagement=self.engagement).distinct().order_by("name")
