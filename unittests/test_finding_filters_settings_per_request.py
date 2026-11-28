"""
The finding filters read the JIRA and finding group settings per instance, not at import.

The JIRA filters (``has_jira_issue`` and its companions) follow ``enable_jira``, the finding group filters
follow ``enable_finding_groups``, and ``has_jira_group_issue`` needs both. They used to be declared in the
class body, so they held what the database said when the module was imported: a setting switched on
afterwards left its filters missing, and one switched off left them in the form, until a restart.
"""

from django.db import connection
from django.test.utils import CaptureQueriesContext

from dojo.filters import get_finding_filterset_fields
from dojo.finding.ui.filters import (
    AcceptedFindingFilter,
    FindingFilter,
    FindingFilterWithoutObjectLookups,
    MetricsFindingFilter,
    ReportFindingFilter,
    SimilarFindingFilterWithoutObjectLookups,
)
from dojo.models import Dojo_User, Finding
from unittests.dojo_test_case import DojoTestCase

JIRA = {"has_jira_issue", "jira_creation", "jira_change", "jira_issue__jira_key", "has_any_jira_issue"}
GROUP_JIRA = {"has_jira_group_issue"}


class TestFindingFiltersFollowSettingsPerInstance(DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User.objects.create(username="filter-settings-user", is_superuser=True, is_staff=True)

    def names(self, filterset_class, **kwargs):
        filterset = filterset_class(None, queryset=Finding.objects.none(), user=self.user, **kwargs)
        # The form shows the filters in their order (less the ones a context hides).
        self.assertEqual([name for name in filterset.filters if name in filterset.form.fields], list(filterset.form.fields))
        return set(filterset.filters), set(filterset.form.fields)

    def check(self, filterset_class, groups, **kwargs):
        cases = [
            (False, False, set()),
            (True, False, JIRA),
            (False, True, groups),
            (True, True, JIRA | groups | GROUP_JIRA),
        ]
        gated = JIRA | groups | GROUP_JIRA
        for jira, finding_groups, expected in cases:
            with self.subTest(filterset=filterset_class.__name__, enable_jira=jira, enable_finding_groups=finding_groups):
                self.system_settings(enable_jira=jira, enable_finding_groups=finding_groups)
                filters, form_fields = self.names(filterset_class, **kwargs)
                self.assertEqual(expected, filters & gated)
                self.assertEqual(expected, form_fields & gated)

    def test_object_lookup_filters(self):
        for filterset_class in (FindingFilter, AcceptedFindingFilter, MetricsFindingFilter):
            self.check(filterset_class, {"has_finding_group", "finding_group"})

    def test_string_matching_filters(self):
        self.check(FindingFilterWithoutObjectLookups, {"has_finding_group", "finding_group__name", "finding_group__name_contains"})
        self.check(SimilarFindingFilterWithoutObjectLookups, {"has_finding_group", "finding_group__name", "finding_group__name_contains"})

    def test_the_report_filter_never_had_them(self):
        gated = JIRA | GROUP_JIRA | {"has_finding_group", "finding_group__name"}
        for jira in (False, True):
            self.system_settings(enable_jira=jira, enable_finding_groups=jira)
            filterset = ReportFindingFilter(None, queryset=Finding.objects.none())
            self.assertEqual(set(), set(filterset.filters) & gated)

    def test_the_classes_declare_every_gated_filter(self):
        self.assertLessEqual(JIRA | GROUP_JIRA | {"has_finding_group", "finding_group"}, set(FindingFilter.base_filters))
        self.assertLessEqual(
            JIRA | GROUP_JIRA | {"has_finding_group", "finding_group__name", "finding_group__name_contains"},
            set(FindingFilterWithoutObjectLookups.base_filters),
        )

    def test_the_full_field_list_reads_no_setting(self):
        with CaptureQueriesContext(connection) as queries:
            fields = get_finding_filterset_fields(all_features=True)
        self.assertEqual(0, len(queries), [query["sql"] for query in queries])
        self.assertLessEqual(JIRA | GROUP_JIRA | {"has_finding_group", "finding_group"}, set(fields))

    def test_the_runtime_field_list_follows_the_settings(self):
        self.system_settings(enable_jira=False, enable_finding_groups=False)
        self.assertEqual(set(), set(get_finding_filterset_fields()) & (JIRA | GROUP_JIRA | {"has_finding_group"}))
        self.system_settings(enable_jira=True, enable_finding_groups=True)
        self.assertLessEqual(JIRA | GROUP_JIRA | {"has_finding_group", "finding_group"}, set(get_finding_filterset_fields()))

    def test_without_finding_groups_has_any_jira_issue_follows_the_meta_fields(self):
        # Meta.fields lists it only with finding groups on; without them it sits among the other declared
        # filters, after the Meta.fields ones, as it did when the class body declared it conditionally.
        for finding_groups, neighbour, offset in ((False, "outside_of_sla", 1), (True, "has_jira_group_issue", -1)):
            self.system_settings(enable_jira=True, enable_finding_groups=finding_groups)
            filterset = FindingFilter(None, queryset=Finding.objects.none(), user=self.user)
            for names in (list(filterset.filters), list(filterset.form.fields)):
                with self.subTest(enable_finding_groups=finding_groups):
                    self.assertEqual(neighbour, names[names.index("has_any_jira_issue") + offset])
