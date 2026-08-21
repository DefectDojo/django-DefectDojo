from django_filters import (
    BooleanFilter,
    CharFilter,
    OrderingFilter,
)

from dojo.endpoint.models import Endpoint
from dojo.filters import CharFieldFilterANDExpression, CharFieldInFilter, DojoFilter


class ApiEndpointFilter(DojoFilter):
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
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("host", "host"),
            ("product", "product"),
            ("id", "id"),
            ("active_finding_count", "active_finding_count"),
        ),
        field_labels={
            "active_finding_count": "Active Findings Count",
        },
    )

    class Meta:
        model = Endpoint
        fields = ["id", "protocol", "userinfo", "host", "port", "path", "query", "fragment", "product"]
