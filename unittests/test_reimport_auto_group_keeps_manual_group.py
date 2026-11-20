# Regression: a reimport that created a new auto group pulled in a finding that already sat in a
# manual group, leaving it in two groups (finding.finding_group then depended on row order).
import json
from io import BytesIO

from django.test import override_settings
from django.utils.timezone import now

from dojo.models import (
    Development_Environment,
    Engagement,
    Finding,
    Finding_Group,
    Product,
    Product_Type,
    Test,
    Test_Type,
    User,
)
from unittests.dojo_test_case import DojoAPITestCase

SCAN_TYPE = "Generic Findings Import"
TITLE = "Rule X"


def _report(*descriptions):
    findings = [{"title": TITLE, "severity": "High", "description": description} for description in descriptions]
    return json.dumps({"findings": findings}).encode()


# Plain http test client: a deployment that forces SECURE_SSL_REDIRECT would answer the API calls with a 301.
@override_settings(SECURE_SSL_REDIRECT=False)
class TestReimportAutoGroupKeepsManualGroup(DojoAPITestCase):

    def setUp(self):
        super().setUp()
        self.admin = User.objects.create_superuser(username="admin", email="admin@example.com", password=None)
        self.login_as_admin()
        self.system_settings(enable_finding_groups=True)
        Development_Environment.objects.get_or_create(name="Development")
        product_type = Product_Type.objects.create(name="Auto Group Manual")
        product = Product.objects.create(name="Auto Group Manual", description="Test", prod_type=product_type)
        engagement = Engagement.objects.create(name="Auto Group Manual", product=product, target_start=now(), target_end=now())
        test_type, _ = Test_Type.objects.get_or_create(name=SCAN_TYPE)
        self.test = Test.objects.create(
            engagement=engagement, test_type=test_type, scan_type=SCAN_TYPE, target_start=now(), target_end=now(),
        )

    def _reimport(self, report, **extra):
        scan = BytesIO(report)
        scan.name = "report.json"
        payload = {
            "test": self.test.id, "scan_type": SCAN_TYPE, "file": scan, "minimum_severity": "Info",
            "active": True, "verified": False, "close_old_findings": False, **extra,
        }
        response = self.client.post("/api/v2/reimport-scan/", payload)
        self.assertEqual(201, response.status_code, response.content[:1000])

    def test_reimport_does_not_put_a_grouped_finding_in_a_second_group(self):
        self._reimport(_report("a"))
        first = Finding.objects.get(test=self.test)
        manual = Finding_Group.objects.create(test=self.test, name="Manual", creator=self.admin)
        manual.findings.add(first)

        self._reimport(_report("a", "b"), group_by="finding_title")

        second = Finding.objects.get(test=self.test, description="b")
        membership = {
            group.name: sorted(group.findings.values_list("description", flat=True))
            for group in Finding_Group.objects.filter(test=self.test)
        }
        self.assertEqual(
            {"Manual": ["a"], f"Findings in: {Finding.persisted_title(TITLE)}": ["b"]}, membership,
            msg=f"finding {first.id} must stay only in its manual group (new finding {second.id}); persisted {membership}",
        )
        groups_of_first = Finding_Group.objects.filter(findings=first).count()
        self.assertEqual(1, groups_of_first, msg=f"finding {first.id} is in {groups_of_first} groups")
