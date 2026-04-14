import datetime

from rest_framework.authtoken.models import Token
from rest_framework.reverse import reverse
from rest_framework.test import APIClient, APITestCase

from dojo.authorization.roles_permissions import Roles
from dojo.models import (
    Engagement,
    Finding,
    Product,
    Product_Member,
    Product_Type,
    Product_Type_Member,
    Role,
    Test,
    Test_Type,
    User,
    Vulnerability_Id,
)


class TestBulkRiskAcceptanceApi(APITestCase):

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create(username="molly", first_name="Molly", last_name="Mocket", is_staff=True)
        cls.token = Token.objects.create(user=cls.user)
        cls.product_type = Product_Type.objects.create(name="Web App")
        cls.product = Product.objects.create(prod_type=cls.product_type, name="Flopper", description="Test product")
        Product_Type_Member.objects.create(product_type=cls.product_type, user=cls.user, role=Role.objects.get(id=Roles.Owner))
        cls.product_2 = Product.objects.create(prod_type=cls.product_type, name="Flopper2", description="Test product2")
        cls.engagement = Engagement.objects.create(product=cls.product, target_start=datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC),
                                                   target_end=datetime.datetime(2000, 2, 1, tzinfo=datetime.UTC))
        cls.engagement_2a = Engagement.objects.create(product=cls.product_2, target_start=datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC),
                                                   target_end=datetime.datetime(2000, 2, 1, tzinfo=datetime.UTC))
        cls.engagement_2b = Engagement.objects.create(product=cls.product_2, target_start=datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC),
                                                   target_end=datetime.datetime(2000, 2, 1, tzinfo=datetime.UTC))

        cls.test_type = Test_Type.objects.create(name="Risk Acceptance Mock Scan", static_tool=True)
        cls.test_a = Test.objects.create(engagement=cls.engagement, test_type=cls.test_type,
                                         target_start=datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC), target_end=datetime.datetime(2000, 2, 1, tzinfo=datetime.UTC))
        cls.test_b = Test.objects.create(engagement=cls.engagement, test_type=cls.test_type,
                                         target_start=datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC), target_end=datetime.datetime(2000, 2, 1, tzinfo=datetime.UTC))
        cls.test_c = Test.objects.create(engagement=cls.engagement, test_type=cls.test_type,
                                         target_start=datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC), target_end=datetime.datetime(2000, 2, 1, tzinfo=datetime.UTC))

        cls.test_d = Test.objects.create(engagement=cls.engagement_2a, test_type=cls.test_type,
                                         target_start=datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC), target_end=datetime.datetime(2000, 2, 1, tzinfo=datetime.UTC))
        cls.test_e = Test.objects.create(engagement=cls.engagement_2b, test_type=cls.test_type,
                                         target_start=datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC), target_end=datetime.datetime(2000, 2, 1, tzinfo=datetime.UTC))

        def create_finding(test: Test, reporter: User, cve: str) -> Finding:
            return Finding(test=test, title=f"Finding {cve}", cve=cve, severity="High", verified=True,
                           description="Hello world!", mitigation="Delete system32", impact="Everything",
                           reporter=reporter, numerical_severity="S1", static_finding=True, dynamic_finding=False)

        Finding.objects.bulk_create(
            create_finding(cls.test_a, cls.user, f"CVE-1999-{i}") for i in range(50, 150, 3))
        for finding in Finding.objects.filter(test=cls.test_a):
            Vulnerability_Id.objects.get_or_create(finding=finding, vulnerability_id=finding.cve)
        Finding.objects.bulk_create(
            create_finding(cls.test_b, cls.user, f"CVE-1999-{i}") for i in range(51, 150, 3))
        for finding in Finding.objects.filter(test=cls.test_b):
            Vulnerability_Id.objects.get_or_create(finding=finding, vulnerability_id=finding.cve)
        Finding.objects.bulk_create(
            create_finding(cls.test_c, cls.user, f"CVE-1999-{i}") for i in range(52, 150, 3))
        for finding in Finding.objects.filter(test=cls.test_c):
            Vulnerability_Id.objects.get_or_create(finding=finding, vulnerability_id=finding.cve)

        Finding.objects.bulk_create(
            create_finding(cls.test_d, cls.user, f"CVE-2000-{i}") for i in range(50, 150, 3))
        for finding in Finding.objects.filter(test=cls.test_d):
            Vulnerability_Id.objects.get_or_create(finding=finding, vulnerability_id=finding.cve)
        Finding.objects.bulk_create(
            create_finding(cls.test_e, cls.user, f"CVE-1999-{i}") for i in range(50, 150, 3))
        for finding in Finding.objects.filter(test=cls.test_e):
            Vulnerability_Id.objects.get_or_create(finding=finding, vulnerability_id=finding.cve)

    def setUp(self) -> None:
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + self.token.key)

    def test_test_accept_risks(self):
        accepted_risks = [{"vulnerability_id": f"CVE-1999-{i}", "justification": "Demonstration purposes",
                           "accepted_by": "King of the Internet"} for i in range(100, 150)]
        result = self.client.post(reverse("test-accept-risks", kwargs={"pk": self.test_a.id}), data=accepted_risks,
                                  format="json")
        self.assertEqual(len(result.json()), 17)
        self.assertEqual(self.test_a.unaccepted_open_findings.count(), 17)
        self.assertEqual(self.test_b.unaccepted_open_findings.count(), 33)
        self.assertEqual(self.test_c.unaccepted_open_findings.count(), 33)

        self.assertEqual(self.test_d.unaccepted_open_findings.count(), 34)
        self.assertEqual(self.engagement_2a.risk_acceptance.count(), 0)

    def test_engagement_accept_risks(self):
        accepted_risks = [{"vulnerability_id": f"CVE-1999-{i}", "justification": "Demonstration purposes",
                           "accepted_by": "King of the Internet"} for i in range(100, 150)]
        result = self.client.post(reverse("engagement-accept-risks", kwargs={"pk": self.engagement.id}),
                                  data=accepted_risks, format="json")
        self.assertEqual(len(result.json()), 50)
        self.assertEqual(self.engagement.unaccepted_open_findings.count(), 50)

        self.assertEqual(self.engagement_2a.risk_acceptance.count(), 0)
        self.assertEqual(self.engagement_2a.unaccepted_open_findings.count(), 34)

    def test_finding_accept_risks(self):
        accepted_risks = [{"vulnerability_id": f"CVE-1999-{i}", "justification": "Demonstration purposes",
                           "accepted_by": "King of the Internet"} for i in range(60, 140)]
        result = self.client.post(reverse("finding-accept-risks"), data=accepted_risks, format="json")
        self.assertEqual(len(result.json()), 106)
        self.assertEqual(Finding.unaccepted_open_findings().count(), 62)

        self.assertEqual(self.engagement_2a.risk_acceptance.count(), 0)
        self.assertEqual(self.engagement_2a.unaccepted_open_findings.count(), 34)

        for ra in self.engagement_2b.risk_acceptance.all():
            for finding in ra.accepted_findings.all():
                self.assertEqual(self.engagement_2a.product, finding.test.engagement.product)


class TestBulkRiskAcceptanceRbac(APITestCase):
    """Tests that accept_risks endpoints use RBAC (Permissions.Risk_Acceptance) instead of is_staff."""

    @classmethod
    def setUpTestData(cls):
        cls.product_type = Product_Type.objects.create(name="RBAC Test Type")
        cls.test_type = Test_Type.objects.create(name="RBAC Mock Scan", static_tool=True)

        # Product with full risk acceptance enabled (default)
        cls.product_enabled = Product.objects.create(
            prod_type=cls.product_type, name="RBAC Enabled",
            description="Full risk acceptance enabled",
            enable_full_risk_acceptance=True,
        )
        # Product with full risk acceptance disabled
        cls.product_disabled = Product.objects.create(
            prod_type=cls.product_type, name="RBAC Disabled",
            description="Full risk acceptance disabled",
            enable_full_risk_acceptance=False,
        )

        cls.engagement_enabled = Engagement.objects.create(
            product=cls.product_enabled,
            target_start=datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC),
            target_end=datetime.datetime(2000, 2, 1, tzinfo=datetime.UTC),
        )
        cls.engagement_disabled = Engagement.objects.create(
            product=cls.product_disabled,
            target_start=datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC),
            target_end=datetime.datetime(2000, 2, 1, tzinfo=datetime.UTC),
        )

        cls.test_enabled = Test.objects.create(
            engagement=cls.engagement_enabled, test_type=cls.test_type,
            target_start=datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC),
            target_end=datetime.datetime(2000, 2, 1, tzinfo=datetime.UTC),
        )
        cls.test_disabled = Test.objects.create(
            engagement=cls.engagement_disabled, test_type=cls.test_type,
            target_start=datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC),
            target_end=datetime.datetime(2000, 2, 1, tzinfo=datetime.UTC),
        )

        # Writer user: has Risk_Acceptance permission, NOT is_staff
        cls.writer = User.objects.create(username="rbac_writer", is_staff=False)
        cls.writer_token = Token.objects.create(user=cls.writer)
        Product_Member.objects.create(
            product=cls.product_enabled, user=cls.writer,
            role=Role.objects.get(id=Roles.Writer),
        )
        Product_Member.objects.create(
            product=cls.product_disabled, user=cls.writer,
            role=Role.objects.get(id=Roles.Writer),
        )

        # Reader user: does NOT have Risk_Acceptance permission, NOT is_staff
        cls.reader = User.objects.create(username="rbac_reader", is_staff=False)
        cls.reader_token = Token.objects.create(user=cls.reader)
        Product_Member.objects.create(
            product=cls.product_enabled, user=cls.reader,
            role=Role.objects.get(id=Roles.Reader),
        )

        def create_finding(test, reporter, cve):
            return Finding(
                test=test, title=f"Finding {cve}", cve=cve, severity="High",
                verified=True, description="Test", mitigation="Test",
                impact="Test", reporter=reporter, numerical_severity="S1",
                static_finding=True, dynamic_finding=False,
            )

        # Findings on the enabled product
        Finding.objects.bulk_create(
            create_finding(cls.test_enabled, cls.writer, f"CVE-2024-{i}") for i in range(10))
        for f in Finding.objects.filter(test=cls.test_enabled):
            Vulnerability_Id.objects.get_or_create(finding=f, vulnerability_id=f.cve)

        # Findings on the disabled product
        Finding.objects.bulk_create(
            create_finding(cls.test_disabled, cls.writer, f"CVE-2024-{i + 100}") for i in range(5))
        for f in Finding.objects.filter(test=cls.test_disabled):
            Vulnerability_Id.objects.get_or_create(finding=f, vulnerability_id=f.cve)

    def _client_for(self, token):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        return client

    def _accepted_risks(self, cve_ids):
        return [{"vulnerability_id": cve, "justification": "Test", "accepted_by": "Tester"} for cve in cve_ids]

    # --- Writer (has Risk_Acceptance) succeeds on enabled product ---

    def test_writer_can_accept_risks_on_engagement(self):
        client = self._client_for(self.writer_token)
        result = client.post(
            reverse("engagement-accept-risks", kwargs={"pk": self.engagement_enabled.id}),
            data=self._accepted_risks(["CVE-2024-0"]),
            format="json",
        )
        self.assertEqual(result.status_code, 201)

    def test_writer_can_accept_risks_on_test(self):
        client = self._client_for(self.writer_token)
        result = client.post(
            reverse("test-accept-risks", kwargs={"pk": self.test_enabled.id}),
            data=self._accepted_risks(["CVE-2024-1"]),
            format="json",
        )
        self.assertEqual(result.status_code, 201)

    def test_writer_can_accept_risks_on_findings(self):
        client = self._client_for(self.writer_token)
        result = client.post(
            reverse("finding-accept-risks"),
            data=self._accepted_risks(["CVE-2024-2"]),
            format="json",
        )
        self.assertEqual(result.status_code, 201)

    # --- Reader (no Risk_Acceptance) is forbidden ---

    def test_reader_forbidden_on_engagement(self):
        client = self._client_for(self.reader_token)
        result = client.post(
            reverse("engagement-accept-risks", kwargs={"pk": self.engagement_enabled.id}),
            data=self._accepted_risks(["CVE-2024-3"]),
            format="json",
        )
        self.assertEqual(result.status_code, 403)

    def test_reader_forbidden_on_test(self):
        client = self._client_for(self.reader_token)
        result = client.post(
            reverse("test-accept-risks", kwargs={"pk": self.test_enabled.id}),
            data=self._accepted_risks(["CVE-2024-4"]),
            format="json",
        )
        self.assertEqual(result.status_code, 403)

    def test_reader_gets_empty_result_on_findings(self):
        client = self._client_for(self.reader_token)
        result = client.post(
            reverse("finding-accept-risks"),
            data=self._accepted_risks(["CVE-2024-5"]),
            format="json",
        )
        # Mass endpoint returns 201 with empty results (no authorized engagements)
        self.assertEqual(result.status_code, 201)
        self.assertEqual(len(result.json()), 0)

    # --- enable_full_risk_acceptance=False blocks risk acceptance ---

    def test_engagement_blocked_when_full_risk_acceptance_disabled(self):
        client = self._client_for(self.writer_token)
        result = client.post(
            reverse("engagement-accept-risks", kwargs={"pk": self.engagement_disabled.id}),
            data=self._accepted_risks(["CVE-2024-100"]),
            format="json",
        )
        self.assertEqual(result.status_code, 403)

    def test_test_blocked_when_full_risk_acceptance_disabled(self):
        client = self._client_for(self.writer_token)
        result = client.post(
            reverse("test-accept-risks", kwargs={"pk": self.test_disabled.id}),
            data=self._accepted_risks(["CVE-2024-101"]),
            format="json",
        )
        self.assertEqual(result.status_code, 403)

    def test_mass_endpoint_skips_disabled_products(self):
        client = self._client_for(self.writer_token)
        # Use a CVE that exists only on the disabled product
        result = client.post(
            reverse("finding-accept-risks"),
            data=self._accepted_risks(["CVE-2024-102"]),
            format="json",
        )
        self.assertEqual(result.status_code, 201)
        # No risk acceptances created because the matching engagement's product has it disabled
        self.assertEqual(len(result.json()), 0)
        # Findings on disabled product remain unaccepted
        self.assertEqual(self.engagement_disabled.unaccepted_open_findings.count(), 5)
