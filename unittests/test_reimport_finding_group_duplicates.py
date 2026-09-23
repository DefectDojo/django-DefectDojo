# Regression: reimport with group_by=finding_title 500s with Finding_Group.MultipleObjectsReturned
from django.utils.timezone import now
from parameterized import parameterized

from dojo.models import Dojo_User, Engagement, Finding, Finding_Group, Test, Test_Type
from dojo.tools.trivy.parser import TrivyParser
from unittests.dojo_test_case import DojoAPITestCase, get_unit_tests_scans_path, versioned_fixtures

SCAN_TYPE = "Trivy Scan"
# One vulnerability, so the create_finding_groups_for_all_findings=False path (which only
# joins an existing group for a lone finding) is exercised as well.
SCAN_FILE = get_unit_tests_scans_path("trivy") / "issue_9092.json"


@versioned_fixtures
class TestReimportFindingGroupDuplicates(DojoAPITestCase):

    """
    Auto-grouping treats a group as one per (test, name). Reimport used to look the group up
    keyed on the importing user as well, which had two effects:

    * a reimport by a different user than the one who created the group made a second
      same-name group in the same test, splitting the findings, and
    * once a test held two same-name groups for the importing user (a raced import), the
      lookup raised Finding_Group.MultipleObjectsReturned and the reimport returned a 500.

    The lookup must reuse the oldest existing group for (test, name), whoever created it.
    """

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.login_as_admin()
        self.admin = self.get_test_admin()
        self.other_user = Dojo_User.objects.create(username="finding-group-original-creator")
        test_type, _ = Test_Type.objects.get_or_create(name=SCAN_TYPE)
        self.test = Test.objects.create(
            engagement=Engagement.objects.get(id=1),
            test_type=test_type,
            scan_type=SCAN_TYPE,
            target_start=now(),
            target_end=now(),
        )
        with SCAN_FILE.open(encoding="utf-8") as scan:
            titles = [finding.title for finding in TrivyParser().get_findings(scan, self.test)]
        self.assertEqual(1, len(titles), msg=f"fixture scan must hold one finding, parsed {titles}")
        self.title = titles[0]
        self.group_name = f"Findings in: {self.title}"

    def _reimport(self, *, create_finding_groups_for_all_findings):
        with SCAN_FILE.open(encoding="utf-8") as scan:
            payload = {
                "test": self.test.id,
                "scan_type": SCAN_TYPE,
                "file": scan,
                "group_by": "finding_title",
                "create_finding_groups_for_all_findings": create_finding_groups_for_all_findings,
                "close_old_findings": True,
                "do_not_reactivate": True,
                "minimum_severity": "Info",
                "active": True,
                "verified": False,
            }
            response = self.client.post("/api/v2/reimport-scan/", payload)
        self.assertEqual(201, response.status_code, response.content[:1000])

    def _assert_findings_in_group(self, expected_group, expected_group_count):
        groups = list(Finding_Group.objects.filter(test=self.test, name=self.group_name).order_by("id"))
        self.assertEqual(
            expected_group_count, len(groups),
            msg=f"expected {expected_group_count} group(s) named {self.group_name!r}, persisted {[(g.id, g.creator.username) for g in groups]}",
        )
        findings = list(Finding.objects.filter(test=self.test))
        # The group name comes from the parsed title; Finding.save() title-cases the stored one.
        self.assertEqual(
            [self.title.lower()], [finding.title.lower() for finding in findings],
            msg=f"expected the one reimported finding in test {self.test.id}",
        )
        for finding in findings:
            membership = list(finding.finding_group_set.values_list("id", flat=True))
            self.assertEqual(
                [expected_group.id], membership,
                msg=f"expected finding {finding.id} only in oldest group {expected_group.id}, persisted in {membership}",
            )

    # create_finding_groups_for_all_findings: True is the API default; False only lets a
    # lone finding join a group that already exists.
    @parameterized.expand([(True,), (False,)])
    def test_reimport_reuses_oldest_of_duplicate_same_name_groups(self, create_all):
        # Two same-name groups owned by the importing user: the state a raced import leaves.
        oldest = Finding_Group.objects.create(test=self.test, name=self.group_name, creator=self.admin)
        Finding_Group.objects.create(test=self.test, name=self.group_name, creator=self.admin)

        self._reimport(create_finding_groups_for_all_findings=create_all)

        self._assert_findings_in_group(oldest, expected_group_count=2)

    @parameterized.expand([(True,), (False,)])
    def test_reimport_by_other_user_reuses_existing_group(self, create_all):
        # The group was made by someone else; the reimport must not start a second one.
        original = Finding_Group.objects.create(test=self.test, name=self.group_name, creator=self.other_user)

        self._reimport(create_finding_groups_for_all_findings=create_all)

        self._assert_findings_in_group(original, expected_group_count=1)

    def test_reimport_creates_group_when_none_exists(self):
        # Control: with no existing group, grouping still creates exactly one, owned by the importer.
        self._reimport(create_finding_groups_for_all_findings=True)

        group = Finding_Group.objects.get(test=self.test, name=self.group_name)
        self.assertEqual(self.admin, group.creator, msg=f"persisted creator={group.creator}")
        self._assert_findings_in_group(group, expected_group_count=1)
