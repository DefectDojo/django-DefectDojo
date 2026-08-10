from django_filters import (
    BooleanFilter,
    CharFilter,
    OrderingFilter,
)

from dojo.filters import (
    CharFieldFilterANDExpression,
    CharFieldInFilter,
    DojoFilter,
)
from dojo.labels import get_labels
from dojo.models import (
    Test,
    Test_Import,
)

labels = get_labels()


class ApiTestFilter(DojoFilter):
    tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Tag name contains")
    tags = CharFieldInFilter(
        field_name="tags__name",
        lookup_expr="in",
        help_text="Comma separated list of exact tags (uses OR for multiple values)")
    tags__and = CharFieldFilterANDExpression(
        field_name="tags__name",
        help_text="Comma separated list of exact tags to match with an AND expression")
    engagement__tags = CharFieldInFilter(
        field_name="engagement__tags__name",
        lookup_expr="in",
        help_text="Comma separated list of exact tags present on engagement (uses OR for multiple values)")
    engagement__tags__and = CharFieldFilterANDExpression(
        field_name="engagement__tags__name",
        help_text="Comma separated list of exact tags to match with an AND expression present on engagement")
    engagement__product__tags = CharFieldInFilter(
        field_name="engagement__product__tags__name",
        lookup_expr="in",
        help_text=labels.ASSET_FILTERS_CSV_TAGS_OR_HELP)
    engagement__product__tags__and = CharFieldFilterANDExpression(
        field_name="engagement__product__tags__name",
        help_text=labels.ASSET_FILTERS_CSV_TAGS_AND_HELP)

    not_tag = CharFilter(field_name="tags__name", lookup_expr="icontains", help_text="Not Tag name contains", exclude="True")
    not_tags = CharFieldInFilter(field_name="tags__name", lookup_expr="in",
                                 help_text="Comma separated list of exact tags not present on model", exclude="True")
    not_engagement__tags = CharFieldInFilter(field_name="engagement__tags__name", lookup_expr="in",
                                                   help_text="Comma separated list of exact tags not present on engagement",
                                                   exclude="True")
    not_engagement__product__tags = CharFieldInFilter(field_name="engagement__product__tags__name",
                                                                  lookup_expr="in",
                                                                  help_text=labels.ASSET_FILTERS_CSV_TAGS_NOT_HELP,
                                                                  exclude="True")
    has_tags = BooleanFilter(field_name="tags", lookup_expr="isnull", exclude=True, label="Has tags")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("title", "title"),
            ("version", "version"),
            ("target_start", "target_start"),
            ("target_end", "target_end"),
            ("test_type", "test_type"),
            ("lead", "lead"),
            ("version", "version"),
            ("branch_tag", "branch_tag"),
            ("build_id", "build_id"),
            ("commit_hash", "commit_hash"),
            ("api_scan_configuration", "api_scan_configuration"),
            ("engagement", "engagement"),
            ("created", "created"),
            ("updated", "updated"),
        ),
        field_labels={
            "name": "Test Name",
        },
    )

    class Meta:
        model = Test
        fields = ["id", "title", "test_type", "target_start",
                     "target_end", "notes", "percent_complete",
                     "engagement", "version",
                     "branch_tag", "build_id", "commit_hash",
                     "api_scan_configuration", "scan_type"]


class TestImportAPIFilter(DojoFilter):
    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("id", "id"),
            ("created", "created"),
            ("modified", "modified"),
            ("version", "version"),
            ("branch_tag", "branch_tag"),
            ("build_id", "build_id"),
            ("commit_hash", "commit_hash"),

        ),
    )

    class Meta:
        model = Test_Import
        fields = ["test",
        "findings_affected",
        "version",
        "branch_tag",
        "build_id",
        "commit_hash",
        "test_import_finding_action__action",
        "test_import_finding_action__finding",
        "test_import_finding_action__created"]
