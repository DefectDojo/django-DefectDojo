import logging

from django_filters import BooleanFilter, CharFilter, MultipleChoiceFilter, OrderingFilter

from dojo.filters import DojoFilter
from dojo.models import IMPORT_ACTIONS, Test_Import, Test_Import_Finding_Action, Test_Type

logger = logging.getLogger(__name__)


class TestImportFilter(DojoFilter):
    version = CharFilter(field_name="version", lookup_expr="icontains")
    version_exact = CharFilter(field_name="version", lookup_expr="iexact", label="Version Exact")
    branch_tag = CharFilter(lookup_expr="icontains", label="Branch/Tag")
    build_id = CharFilter(lookup_expr="icontains", label="Build ID")
    commit_hash = CharFilter(lookup_expr="icontains", label="Commit hash")

    findings_affected = BooleanFilter(field_name="findings_affected", lookup_expr="isnull", exclude=True, label="Findings affected")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("date", "date"),
            ("version", "version"),
            ("branch_tag", "branch_tag"),
            ("build_id", "build_id"),
            ("commit_hash", "commit_hash"),

        ),
    )

    class Meta:
        model = Test_Import
        fields = []


class TestImportFindingActionFilter(DojoFilter):
    action = MultipleChoiceFilter(choices=IMPORT_ACTIONS)
    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("action", "action"),
        ),
    )

    class Meta:
        model = Test_Import_Finding_Action
        fields = []


class TestTypeFilter(DojoFilter):
    name = CharFilter(lookup_expr="icontains")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("name", "name"),
        ),
    )

    class Meta:
        model = Test_Type
        exclude = []
        include = ("name",)
