from django_filters import (
    BooleanFilter,
    CharFilter,
    OrderingFilter,
)

from dojo.filters import (
    CharFieldFilterANDExpression,
    CharFieldInFilter,
    DojoFilter,
    NumberInFilter,
)
from dojo.labels import get_labels
from dojo.models import Engagement

labels = get_labels()


class ApiEngagementFilter(DojoFilter):
    product__prod_type = NumberInFilter(field_name="product__prod_type", lookup_expr="in")
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Tag name contains")
    tags = CharFieldInFilter(
        field_name="tags__name",
        lookup_expr="in",
        help_text="Comma separated list of exact tags (uses OR for multiple values)")
    tags__and = CharFieldFilterANDExpression(
        field_name="tags__name",
        help_text="Comma separated list of exact tags to match with an AND expression")
    product__tags = CharFieldInFilter(
        field_name="product__tags__name",
        lookup_expr="in",
        help_text=labels.ASSET_FILTERS_CSV_TAGS_OR_HELP)
    product__tags__and = CharFieldFilterANDExpression(
        field_name="product__tags__name",
        help_text=labels.ASSET_FILTERS_CSV_TAGS_AND_HELP)

    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Not Tag name contains", exclude="True")
    not_tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                                 help_text="Comma separated list of exact tags not present on model", exclude="True")
    not_product__tags = CharFieldInFilter(field_name="product__tags__name",
                                                lookup_expr="in",
                                                help_text=labels.ASSET_FILTERS_CSV_TAGS_NOT_HELP,
                                                exclude="True")
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("name", "name"),
            ("version", "version"),
            ("target_start", "target_start"),
            ("target_end", "target_end"),
            ("status", "status"),
            ("lead", "lead"),
            ("created", "created"),
            ("updated", "updated"),
        ),
        field_labels={
            "name": "Engagement Name",
        },

    )

    class Meta:
        model = Engagement
        fields = ["id", "active", "target_start",
                     "target_end", "requester", "report_type",
                     "updated", "threat_model", "api_test",
                     "pen_test", "status", "product", "name", "version", "tags"]
