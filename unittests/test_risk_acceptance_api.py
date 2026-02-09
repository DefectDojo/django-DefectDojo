import datetime

from rest_framework.authtoken.models import Token
from rest_framework.reverse import reverse
from rest_framework.test import APIClient, APITestCase

from dojo.authorization.roles_permissions import Roles
from dojo.models import (
    Engagement,
    Finding,
    Product,
    Product_Type,
    Product_Type_Member,
    Risk_Acceptance,
    Role,
    Test,
    Test_Type,
    User,
)


class TestRiskAcceptanceApi(APITestCase):

    """
    Comprehensive API tests for Risk Acceptance creation and updates.
    Tests edge cases, validations, and engagement linking.
    """

    @classmethod
    def setUpTestData(cls):
        # Create user with permissions
        cls.user = User.objects.create(username="test_user", first_name="Test", last_name="User", is_staff=True)
        cls.token = Token.objects.create(user=cls.user)

        # Create product type
        cls.product_type = Product_Type.objects.create(name="Test Product Type")
        Product_Type_Member.objects.create(product_type=cls.product_type, user=cls.user, role=Role.objects.get(id=Roles.Owner))

        # Create product with full risk acceptance enabled
        cls.product_enabled = Product.objects.create(
            prod_type=cls.product_type,
            name="Product with RA Enabled",
            description="Test product with full risk acceptance enabled",
            enable_full_risk_acceptance=True,
        )

        # Create product with full risk acceptance disabled
        cls.product_disabled = Product.objects.create(
            prod_type=cls.product_type,
            name="Product with RA Disabled",
            description="Test product with full risk acceptance disabled",
            enable_full_risk_acceptance=False,
        )

        # Create engagements
        cls.engagement_a = Engagement.objects.create(
            product=cls.product_enabled,
            target_start=datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC),
            target_end=datetime.datetime(2000, 2, 1, tzinfo=datetime.UTC),
            name="Engagement A",
        )

        cls.engagement_b = Engagement.objects.create(
            product=cls.product_enabled,
            target_start=datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC),
            target_end=datetime.datetime(2000, 2, 1, tzinfo=datetime.UTC),
            name="Engagement B",
        )

        cls.engagement_disabled = Engagement.objects.create(
            product=cls.product_disabled,
            target_start=datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC),
            target_end=datetime.datetime(2000, 2, 1, tzinfo=datetime.UTC),
            name="Engagement Disabled",
        )

        # Create test type and tests
        cls.test_type = Test_Type.objects.create(name="API Test Scan", static_tool=True)

        cls.test_a1 = Test.objects.create(
            engagement=cls.engagement_a,
            test_type=cls.test_type,
            target_start=datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC),
            target_end=datetime.datetime(2000, 2, 1, tzinfo=datetime.UTC),
        )

        cls.test_b1 = Test.objects.create(
            engagement=cls.engagement_b,
            test_type=cls.test_type,
            target_start=datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC),
            target_end=datetime.datetime(2000, 2, 1, tzinfo=datetime.UTC),
        )

        cls.test_disabled = Test.objects.create(
            engagement=cls.engagement_disabled,
            test_type=cls.test_type,
            target_start=datetime.datetime(2000, 1, 1, tzinfo=datetime.UTC),
            target_end=datetime.datetime(2000, 2, 1, tzinfo=datetime.UTC),
        )

        # Create findings
        cls.finding_a1 = Finding.objects.create(
            test=cls.test_a1,
            title="Finding A1",
            severity="High",
            verified=True,
            description="Test finding in engagement A",
            reporter=cls.user,
            numerical_severity="S1",
            static_finding=True,
            dynamic_finding=False,
        )

        cls.finding_a2 = Finding.objects.create(
            test=cls.test_a1,
            title="Finding A2",
            severity="Medium",
            verified=True,
            description="Another test finding in engagement A",
            reporter=cls.user,
            numerical_severity="S2",
            static_finding=True,
            dynamic_finding=False,
        )

        cls.finding_a3 = Finding.objects.create(
            test=cls.test_a1,
            title="Finding A3",
            severity="Low",
            verified=True,
            description="Third test finding in engagement A",
            reporter=cls.user,
            numerical_severity="S3",
            static_finding=True,
            dynamic_finding=False,
        )

        cls.finding_b1 = Finding.objects.create(
            test=cls.test_b1,
            title="Finding B1",
            severity="High",
            verified=True,
            description="Test finding in engagement B",
            reporter=cls.user,
            numerical_severity="S1",
            static_finding=True,
            dynamic_finding=False,
        )

        cls.finding_b2 = Finding.objects.create(
            test=cls.test_b1,
            title="Finding B2",
            severity="Medium",
            verified=True,
            description="Another test finding in engagement B",
            reporter=cls.user,
            numerical_severity="S2",
            static_finding=True,
            dynamic_finding=False,
        )

        cls.finding_disabled = Finding.objects.create(
            test=cls.test_disabled,
            title="Finding Disabled",
            severity="High",
            verified=True,
            description="Test finding in disabled engagement",
            reporter=cls.user,
            numerical_severity="S1",
            static_finding=True,
            dynamic_finding=False,
        )

    def setUp(self):
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + self.token.key)
        self.url = reverse("risk_acceptance-list")

    def test_create_risk_acceptance_links_to_engagement(self):
        """Test that risk acceptance created via API appears in engagement.risk_acceptance"""
        payload = {
            "name": "Test Risk Acceptance",
            "recommendation": "A",
            "recommendation_details": "Test recommendation",
            "decision": "A",
            "decision_details": "Test decision",
            "accepted_by": "Test User",
            "owner": self.user.id,
            "expiration_date": "2025-12-31T23:59:59Z",
            "reactivate_expired": True,
            "restart_sla_expired": False,
            "accepted_findings": [self.finding_a1.id, self.finding_a2.id],
        }

        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(201, response.status_code, response.content)

        # Verify risk acceptance was created
        ra_id = response.data["id"]
        risk_acceptance = Risk_Acceptance.objects.get(id=ra_id)

        # Verify it's linked to the engagement
        self.assertIn(risk_acceptance, self.engagement_a.risk_acceptance.all())
        self.assertEqual(1, self.engagement_a.risk_acceptance.count())

        # Verify findings are marked as risk accepted
        self.finding_a1.refresh_from_db()
        self.finding_a2.refresh_from_db()
        self.assertTrue(self.finding_a1.risk_accepted)
        self.assertTrue(self.finding_a2.risk_accepted)

    def test_create_risk_acceptance_multiple_engagements_fails(self):
        """Test that creating risk acceptance with findings from multiple engagements fails"""
        payload = {
            "name": "Invalid Risk Acceptance",
            "recommendation": "A",
            "decision": "A",
            "accepted_by": "Test User",
            "owner": self.user.id,
            "accepted_findings": [self.finding_a1.id, self.finding_b1.id],  # Different engagements!
        }

        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(403, response.status_code, response.content)
        self.assertIn("multiple engagements", str(response.data))

    def test_create_risk_acceptance_product_disabled_fails(self):
        """Test that creating risk acceptance fails when product has enable_full_risk_acceptance=False"""
        payload = {
            "name": "Disabled Product Risk Acceptance",
            "recommendation": "A",
            "decision": "A",
            "accepted_by": "Test User",
            "owner": self.user.id,
            "accepted_findings": [self.finding_disabled.id],
        }

        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(403, response.status_code, response.content)
        self.assertIn("not enabled", str(response.data))

        # Verify no risk acceptance was created
        self.assertEqual(0, self.engagement_disabled.risk_acceptance.count())

    def test_update_risk_acceptance_add_findings_same_engagement(self):
        """Test that updating to add more findings from same engagement succeeds"""
        # Create risk acceptance with one finding
        ra = Risk_Acceptance.objects.create(
            name="Initial RA",
            recommendation="A",
            decision="A",
            accepted_by="Test User",
            owner=self.user,
        )
        ra.accepted_findings.add(self.finding_a1)
        self.engagement_a.risk_acceptance.add(ra)

        # Update to add another finding from same engagement
        payload = {
            "name": "Updated RA",
            "recommendation": "A",
            "decision": "A",
            "accepted_by": "Test User",
            "owner": self.user.id,
            "accepted_findings": [self.finding_a1.id, self.finding_a2.id],
        }

        response = self.client.put(f"{self.url}{ra.id}/", payload, format="json")
        self.assertEqual(200, response.status_code, response.content)

        # Verify both findings are now in the risk acceptance
        ra.refresh_from_db()
        self.assertEqual(2, ra.accepted_findings.count())
        self.assertIn(self.finding_a1, ra.accepted_findings.all())
        self.assertIn(self.finding_a2, ra.accepted_findings.all())

    def test_update_risk_acceptance_switch_engagement_fails(self):
        """Test that replacing all findings with findings from different engagement fails"""
        # Create risk acceptance with findings from engagement A
        ra = Risk_Acceptance.objects.create(
            name="RA for Engagement A",
            recommendation="A",
            decision="A",
            accepted_by="Test User",
            owner=self.user,
        )
        ra.accepted_findings.add(self.finding_a1)
        self.engagement_a.risk_acceptance.add(ra)

        # Try to replace with finding from engagement B
        payload = {
            "name": "RA for Engagement A",
            "recommendation": "A",
            "decision": "A",
            "accepted_by": "Test User",
            "owner": self.user.id,
            "accepted_findings": [self.finding_b1.id],  # Different engagement!
        }

        response = self.client.put(f"{self.url}{ra.id}/", payload, format="json")
        # Returns 403 because the validate_findings_have_same_engagement check runs first
        self.assertEqual(403, response.status_code, response.content)
        self.assertIn("multiple engagements", str(response.data))

    def test_update_risk_acceptance_empty_then_different_engagement_fails(self):
        """Test edge case: risk acceptance with no findings cannot accept findings from different engagement"""
        # Create risk acceptance with findings from engagement A, then remove them
        ra = Risk_Acceptance.objects.create(
            name="RA for Engagement A",
            recommendation="A",
            decision="A",
            accepted_by="Test User",
            owner=self.user,
        )
        ra.accepted_findings.add(self.finding_a1)
        self.engagement_a.risk_acceptance.add(ra)

        # Remove all findings (make it empty)
        ra.accepted_findings.clear()

        # Try to add finding from engagement B
        payload = {
            "name": "RA for Engagement A",
            "recommendation": "A",
            "decision": "A",
            "accepted_by": "Test User",
            "owner": self.user.id,
            "accepted_findings": [self.finding_b1.id],  # Different engagement!
        }

        response = self.client.put(f"{self.url}{ra.id}/", payload, format="json")
        self.assertEqual(400, response.status_code, response.content)
        self.assertIn("belongs to engagement", str(response.data))

    def test_update_risk_acceptance_add_cross_engagement_fails(self):
        """Test that adding findings from different engagement while keeping existing ones fails"""
        # Create risk acceptance with finding from engagement A
        ra = Risk_Acceptance.objects.create(
            name="RA for Engagement A",
            recommendation="A",
            decision="A",
            accepted_by="Test User",
            owner=self.user,
        )
        ra.accepted_findings.add(self.finding_a1)
        self.engagement_a.risk_acceptance.add(ra)

        # Try to add findings from both engagements
        payload = {
            "name": "RA for Engagement A",
            "recommendation": "A",
            "decision": "A",
            "accepted_by": "Test User",
            "owner": self.user.id,
            "accepted_findings": [self.finding_a1.id, self.finding_b1.id],  # Mixed engagements!
        }

        response = self.client.put(f"{self.url}{ra.id}/", payload, format="json")
        self.assertEqual(403, response.status_code, response.content)
        self.assertIn("multiple engagements", str(response.data))
