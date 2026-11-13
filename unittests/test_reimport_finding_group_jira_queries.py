# Regression: a reimport with group_by and JIRA keep-in-sync read each finding group and its JIRA issue one
# query at a time, and looked the reactivated/unchanged groups up through a subquery whose plan could degrade
# to one index probe per membership per group.
from unittest.mock import patch

from crum import impersonate
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from parameterized import parameterized

from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import (
    Development_Environment,
    Engagement,
    Finding,
    Finding_Group,
    JIRA_Instance,
    JIRA_Issue,
    JIRA_Project,
    Product,
    Product_Type,
    Test,
    Test_Type,
    User,
)

from .dojo_test_case import DojoTestCase

SCAN_TYPE = "Generic Findings Import"


class TestReimportFindingGroupJiraQueries(DojoTestCase):

    """
    process_groups_for_all_findings() decides, per group of the reimport and per group of its
    reactivated or unchanged findings, whether to push the group to JIRA. The decision reads the
    group and its JIRA issue: those reads are batched, so the queries do not grow with the number
    of groups, and the pushes (which objects, in which order) stay what they were.
    """

    def setUp(self):
        super().setUp()
        self.user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="group_jira_queries")
        self.environment, _ = Development_Environment.objects.get_or_create(name="Development")
        product, _ = Product.objects.get_or_create(name="TestReimportFindingGroupJiraQueries", description="Test", prod_type=product_type)
        engagement = Engagement.objects.create(
            name="Group JIRA Engagement", product=product, target_start=timezone.now(), target_end=timezone.now(),
        )
        test_type, _ = Test_Type.objects.get_or_create(name=SCAN_TYPE)
        self.test = Test.objects.create(
            engagement=engagement, test_type=test_type, scan_type=SCAN_TYPE,
            target_start=timezone.now(), target_end=timezone.now(),
        )
        self.jira_instance = JIRA_Instance.objects.create(
            configuration_name="group jira queries", url="https://jira.example.com", username="user", password="token",  # noqa: S106
            default_issue_type="Bug", epic_name_id=1, open_status_key=1, close_status_key=2,
            info_mapping_severity="Info", low_mapping_severity="Low", medium_mapping_severity="Medium",
            high_mapping_severity="High", critical_mapping_severity="Critical", finding_jira_sync=True,
        )
        self.jira_project = JIRA_Project.objects.create(jira_instance=self.jira_instance, product=product, project_key="GJQ")

    def _findings(self, titles, **fields):
        findings = Finding.objects.bulk_create([
            Finding(test=self.test, title=title, severity="High", reporter=self.user, numerical_severity="S1", **fields)
            for title in titles
        ])
        return list(Finding.objects.filter(id__in=[f.id for f in findings]).order_by("id"))

    def _group(self, name, findings, *, jira):
        group = Finding_Group.objects.create(test=self.test, name=name, creator=self.user)
        group.findings.add(*findings)
        if jira:
            JIRA_Issue.objects.create(jira_project=self.jira_project, jira_id=name, jira_key=f"GJQ-{group.id}", finding_group=group)
        return group

    def _reimporter(self, groups, reactivated, unchanged, *, push_to_jira=False, create_all=True):
        reimporter = DefaultReImporter(
            test=self.test, user=self.user, lead=self.user, scan_date=None, environment=self.environment,
            active=True, verified=False, scan_type=SCAN_TYPE, close_old_findings=False,
            group_by="finding_title", create_finding_groups_for_all_findings=create_all, push_to_jira=push_to_jira,
        )
        reimporter.jira_instance = self.jira_instance
        reimporter.findings_groups_enabled = True
        reimporter.group_names_to_findings_dict = groups
        reimporter.reactivated_items = reactivated
        reimporter.unchanged_items = unchanged
        return reimporter

    def _scenario(self, group_count):
        """
        ``group_count`` groups the reimport adds a new finding to, each with an older member, half with a JIRA
        issue; and as many older groups whose only member is an unchanged finding, half with a JIRA issue.
        Returns the reimporter and the objects a push must reach, in push order.
        """
        groups, unchanged = {}, []
        for index in range(group_count):
            name = f"incoming {index}"
            old, new = self._findings([name, name])
            self._group(name, [old], jira=index % 2 == 0)
            groups[name] = [new]
        for index in range(group_count):
            name = f"unchanged {index}"
            [finding] = self._findings([name])
            self._group(name, [finding], jira=index % 2 == 0)
            unchanged.append(finding.id)
        # Mitigated findings do not bring their group along, even when it has a JIRA issue.
        [mitigated] = self._findings(["mitigated"], is_mitigated=True)
        self._group("mitigated", [mitigated], jira=True)
        unchanged.append(mitigated.id)
        # The incoming groups' older members are unchanged too, so the second pass reaches those groups again
        # (pushed once per pass, as before): every JIRA-linked group but the mitigated one, by id.
        unchanged.extend(Finding_Group.findings.through.objects.filter(finding_group__name__startswith="incoming").values_list("finding_id", flat=True))
        expected = [g for g in Finding_Group.objects.filter(name__startswith="incoming").order_by("id") if g.has_jira_issue]
        expected.extend(g for g in Finding_Group.objects.filter(test=self.test).exclude(name="mitigated").order_by("id") if g.has_jira_issue)
        return self._reimporter(groups, [], unchanged), expected

    def _run(self, reimporter):
        pushed = []
        with (
            impersonate(self.user),
            patch("dojo.importers.default_reimporter.jira_services.push", side_effect=pushed.append),
            CaptureQueriesContext(connection) as queries,
        ):
            reimporter.process_groups_for_all_findings()
        return pushed, queries

    def test_group_lookups_do_not_grow_with_the_number_of_groups(self):
        """Ten times the groups, the same number of queries; each JIRA-linked group pushed, in order."""
        counts = {}
        for group_count in (2, 20):
            Finding_Group.objects.filter(test=self.test).delete()
            Finding.objects.filter(test=self.test).delete()
            reimporter, expected = self._scenario(group_count)
            pushed, queries = self._run(reimporter)
            self.assertEqual(
                [(type(o).__name__, o.id) for o in pushed], [(type(o).__name__, o.id) for o in expected],
                f"pushes with {group_count} groups",
            )
            counts[group_count] = len(queries)
        self.assertEqual(
            counts[2], counts[20],
            f"process_groups_for_all_findings ran {counts[2]} queries for 2 groups and {counts[20]} for 20",
        )

    def test_unchanged_groups_are_read_by_id_not_through_a_subquery(self):
        """The reactivated/unchanged groups are read from id lists; a subquery over dojo_finding planned badly at scale."""
        reimporter, _expected = self._scenario(3)
        _pushed, queries = self._run(reimporter)
        group_reads = [q["sql"] for q in queries.captured_queries if q["sql"].startswith('SELECT "dojo_finding_group"."id"')]
        self.assertTrue(group_reads, "the unchanged groups were not read")
        for sql in group_reads:
            self.assertNotIn("IN (SELECT", sql, f"group lookup still goes through a subquery: {sql[:300]}")

    @parameterized.expand([
        ("own_jira_issue", True, True),
        ("no_jira_issue", False, False),
    ])
    def test_ungrouped_finding_is_pushed_itself_when_kept_in_sync(self, case, has_issue, expect_push):
        """A lone finding left out of a group is pushed on its own JIRA issue, as before."""
        [finding] = self._findings(["lone"])
        if has_issue:
            JIRA_Issue.objects.create(jira_project=self.jira_project, jira_id="lone", jira_key="GJQ-lone", finding=finding)
        reimporter = self._reimporter({"lone": [finding]}, [], [], create_all=False)
        pushed, _queries = self._run(reimporter)
        self.assertEqual(Finding_Group.objects.filter(test=self.test).count(), 0, "a lone finding formed a group")
        self.assertEqual(
            [(type(o).__name__, o.id) for o in pushed], [("Finding", finding.id)] if expect_push else [], f"pushes, {case}",
        )

    def test_push_to_jira_pushes_every_group_without_reading_issues(self):
        """With push_to_jira set the JIRA issue is not consulted, and every group is pushed."""
        reimporter, _expected = self._scenario(4)
        reimporter.push_to_jira = True
        pushed, _queries = self._run(reimporter)
        incoming = list(Finding_Group.objects.filter(name__startswith="incoming").order_by("id"))
        unchanged = list(Finding_Group.objects.filter(test=self.test).exclude(name="mitigated").order_by("id"))
        self.assertEqual([o.id for o in pushed], [g.id for g in incoming] + [g.id for g in unchanged])
