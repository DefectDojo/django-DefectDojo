# Regression: with group_by=finding_title, an import named each finding group from the
# saved (title-cased) finding title, but a reimport named a new finding's group from the
# parsed title before save title-cased it. For a report whose titles are not already
# title-cased, the reimport's new findings landed in a second group with no JIRA issue, so
# JIRA keep-in-sync never pushed them to the issue of the group they belong to.
from unittest.mock import patch

from django.test import override_settings
from django.utils import timezone

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
    User,
)

from .dojo_test_case import DojoAPITestCase, get_unit_tests_scans_path

SCAN_TYPE = "Generic Findings Import"
TITLES = ["Group Jira Rule 0", "Group Jira Rule 1"]


@override_settings(SECURE_SSL_REDIRECT=False)
class TestReimportGroupByTitleCase(DojoAPITestCase):

    maxDiff = None

    def setUp(self):
        super().setUp()
        User.objects.get_or_create(username="admin", defaults={"is_staff": True, "is_superuser": True})
        Development_Environment.objects.get_or_create(name="Development")
        self.system_settings(enable_jira=True)
        self.login_as_admin()
        product_type = Product_Type.objects.create(name="Group By Title Case")
        product = Product.objects.create(name="Group By Title Case", description="Test", prod_type=product_type)
        self.engagement = Engagement.objects.create(
            name="Group By Title Case", product=product, target_start=timezone.now(), target_end=timezone.now(),
        )
        jira_instance = JIRA_Instance.objects.create(
            configuration_name="group by title case", url="https://jira.example.com", username="user", password="token",  # noqa: S106
            default_issue_type="Bug", epic_name_id=1, open_status_key=1, close_status_key=2,
            info_mapping_severity="Info", low_mapping_severity="Low", medium_mapping_severity="Medium",
            high_mapping_severity="High", critical_mapping_severity="Critical", finding_jira_sync=True,
        )
        self.jira_project = JIRA_Project.objects.create(jira_instance=jira_instance, product=product, project_key="GTC")
        self.report = get_unit_tests_scans_path("generic") / "generic_lowercase_titles_group.json"
        self.report_with_new = get_unit_tests_scans_path("generic") / "generic_lowercase_titles_group_new.json"

    def _groups(self, test_id):
        return {
            group.name: sorted(group.findings.values_list("title", "description"))
            for group in Finding_Group.objects.filter(test_id=test_id)
        }

    def test_reimport_new_findings_join_the_import_group_and_its_jira_issue(self):
        with patch("dojo.jira.helper.push_to_jira") as push:
            test_id = self.import_scan_with_params(
                self.report, scan_type=SCAN_TYPE, engagement=self.engagement.id, group_by="finding_title", verified=True,
            )["test"]
        push.assert_not_called()
        # the import stores title-cased titles and names its groups from them
        self.assertEqual(
            {f"Findings in: {title}" for title in TITLES},
            set(self._groups(test_id)),
        )
        # what an earlier push of each group to JIRA left behind
        groups = {group.name: group for group in Finding_Group.objects.filter(test_id=test_id)}
        for group in groups.values():
            JIRA_Issue.objects.create(jira_project=self.jira_project, jira_id=group.name, jira_key=f"GTC-{group.id}", finding_group=group)

        with patch("dojo.jira.helper.push_to_jira") as push:
            self.reimport_scan_with_params(
                test_id, self.report_with_new, scan_type=SCAN_TYPE, engagement=self.engagement.id, group_by="finding_title", verified=True,
            )

        self.assertEqual(4, Finding.objects.filter(test_id=test_id).count())
        # one group per title, holding the imported finding and the reimport's new one
        self.assertEqual(
            {
                f"Findings in: {title}": [(title, f"first finding of {title[-6:].lower()}"), (title, f"second finding of {title[-6:].lower()}")]
                for title in TITLES
            },
            self._groups(test_id),
        )
        # keep-in-sync pushes each group with its new finding to that group's JIRA issue
        pushed_groups = {call.args[0] for call in push.call_args_list if isinstance(call.args[0], Finding_Group)}
        self.assertEqual(set(groups.values()), pushed_groups)
