"""Tests for the optimized view_engineer metrics endpoint"""

from datetime import datetime, timedelta
from unittest.mock import patch

from django.test import RequestFactory, override_settings
from django.urls import reverse
from django.utils import timezone

from dojo.models import Finding, Risk_Acceptance, User
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


@override_settings(CELERY_TASK_ALWAYS_EAGER=True)
@versioned_fixtures
class ViewEngineerMetricsTest(DojoTestCase):

    """Test suite for the optimized view_engineer endpoint"""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        """Set up test data and common objects"""
        self.factory = RequestFactory()
        self.user1 = User.objects.get(username="user1")
        self.user2 = User.objects.get(username="user2")
        self.superuser = User.objects.get(username="admin")

        self.test_findings = []
        self.create_test_findings()

    def create_test_findings(self):
        """Create test findings with different severities and dates"""
        now = timezone.now()

        # Current month findings
        for severity in ["Critical", "High", "Medium", "Low"]:
            finding = Finding.objects.create(
                title=f"Test Finding {severity}",
                description=f"Test finding with {severity} severity",
                severity=severity,
                date=now.replace(day=15),
                reporter=self.user1,
                test_id=3,
                verified=True,
                active=True,
                mitigated=None,
            )
            self.test_findings.append(finding)

        # Previous month findings
        prev_month = now - timedelta(days=30)
        for severity in ["Critical", "High"]:
            finding = Finding.objects.create(
                title=f"Old Test Finding {severity}",
                description=f"Old test finding with {severity} severity",
                severity=severity,
                date=prev_month,
                reporter=self.user1,
                test_id=3,
                verified=True,
                active=True,
                mitigated=None,
            )
            self.test_findings.append(finding)

        # Closed findings
        for severity in ["High", "Medium"]:
            finding = Finding.objects.create(
                title=f"Closed Test Finding {severity}",
                description=f"Closed test finding with {severity} severity",
                severity=severity,
                date=now.replace(day=10),
                reporter=self.user1,
                test_id=3,
                verified=True,
                active=False,
                mitigated=now.replace(day=20),
                mitigated_by=self.user1,
            )
            self.test_findings.append(finding)

    def test_view_engineer_permission_denied_anonymous(self):
        """Test that anonymous users cannot access view_engineer"""
        response = self.client.get(reverse("view_engineer", args=[self.user1.id]))
        self.assertEqual(response.status_code, 302)

    def test_view_engineer_permission_denied_other_user(self):
        """Test that regular users cannot view other users' metrics"""
        self.client.force_login(self.user2)
        response = self.client.get(reverse("view_engineer", args=[self.user1.id]))
        # Django test client may return 400 or 403 for permission denied
        self.assertIn(response.status_code, [400, 403])

    def test_view_engineer_permission_allowed_self(self):
        """Test that users can view their own metrics"""
        self.client.force_login(self.user1)
        response = self.client.get(reverse("view_engineer", args=[self.user1.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.user1.get_full_name())

    def test_view_engineer_permission_allowed_superuser(self):
        """Test that superusers can view any user's metrics"""
        self.client.force_login(self.superuser)
        response = self.client.get(reverse("view_engineer", args=[self.user1.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.user1.get_full_name())

    @patch("django.utils.timezone.now")
    def test_view_engineer_monthly_metrics_calculation(self, mock_now):
        """Test that monthly metrics are calculated correctly"""
        fixed_now = timezone.make_aware(datetime(2023, 6, 15, 10, 0, 0))
        mock_now.return_value = fixed_now

        # Create findings for this specific month
        Finding.objects.create(
            title="June Critical Finding",
            severity="Critical",
            date=fixed_now.replace(day=10),
            reporter=self.user1,
            test_id=3,
            verified=True,
            active=True,
        )
        Finding.objects.create(
            title="June High Finding",
            severity="High",
            date=fixed_now.replace(day=12),
            reporter=self.user1,
            test_id=3,
            verified=True,
            active=True,
        )

        self.client.force_login(self.user1)
        response = self.client.get(reverse("view_engineer", args=[self.user1.id]))
        context = response.context

        # Test actual counts, not just key existence
        self.assertEqual(context["critical_open_month"], 1)
        self.assertEqual(context["high_open_month"], 1)
        # open_month is a QuerySet
        self.assertGreaterEqual(context["open_month"].count(), 2)

    @patch("django.utils.timezone.now")
    def test_view_engineer_weekly_metrics_calculation(self, mock_now):
        """Test that weekly metrics are calculated correctly"""
        fixed_now = timezone.make_aware(datetime(2023, 6, 15, 10, 0, 0))
        mock_now.return_value = fixed_now

        # Create findings for this week
        Finding.objects.create(
            title="This Week Finding",
            severity="High",
            date=fixed_now.replace(day=12),  # Same week
            reporter=self.user1,
            test_id=3,
            verified=True,
            active=True,
        )

        self.client.force_login(self.user1)
        response = self.client.get(reverse("view_engineer", args=[self.user1.id]))
        context = response.context

        # Test that we have weekly data
        if isinstance(context["open_week_count"], dict):
            self.assertGreater(sum(context["open_week_count"].values()), 0)
        else:
            self.assertGreaterEqual(context["open_week_count"], 1)

        # Test that open_week contains our test finding
        self.assertGreater(context["open_week"].count(), 0)

    @patch("django.utils.timezone.now")
    def test_view_engineer_age_buckets_calculation(self, mock_now):
        """Test age bucket calculations using DB aggregation"""
        fixed_now = timezone.make_aware(datetime(2023, 6, 15, 10, 0, 0))
        mock_now.return_value = fixed_now

        # Create findings with specific ages
        Finding.objects.create(
            title="Recent Finding",
            severity="High",
            date=fixed_now - timedelta(days=15),  # Less than 30 days
            reporter=self.user1,
            test_id=3,
            verified=True,
            active=True,
        )
        Finding.objects.create(
            title="Old Finding",
            severity="Medium",
            date=fixed_now - timedelta(days=100),  # More than 90 days
            reporter=self.user1,
            test_id=3,
            verified=True,
            active=True,
        )

        self.client.force_login(self.user1)
        response = self.client.get(reverse("view_engineer", args=[self.user1.id]))
        context = response.context

        # Test actual age bucket counts
        self.assertGreaterEqual(context["lt"], 1)  # Recent finding
        self.assertGreaterEqual(context["mn"], 1)  # Old finding

        # Verify they are integers from DB aggregation
        self.assertIsInstance(context["lt"], int)
        self.assertIsInstance(context["mn"], int)

    @patch("django.utils.timezone.now")
    def test_view_engineer_risk_acceptance_metrics(self, mock_now):
        """Test risk acceptance handling in metrics"""
        fixed_now = timezone.make_aware(datetime(2023, 6, 15, 10, 0, 0))
        mock_now.return_value = fixed_now

        # Create a finding and accept it
        finding = Finding.objects.create(
            title="Finding to Accept",
            severity="High",
            date=fixed_now,
            reporter=self.user1,
            test_id=3,
            verified=True,
            active=True,
        )

        risk_acceptance = Risk_Acceptance.objects.create(
            name="Test Risk Acceptance",
            recommendation="A",
            decision="A",
            owner=self.user1,
            created=fixed_now,
        )
        risk_acceptance.accepted_findings.add(finding)

        self.client.force_login(self.user1)
        response = self.client.get(reverse("view_engineer", args=[self.user1.id]))
        context = response.context

        # Test that accepted findings are counted
        self.assertGreaterEqual(context["high_a_month"], 1)
        # a_month is a QuerySet
        self.assertGreaterEqual(context["a_month"].count(), 1)

    def test_view_engineer_chart_data_structure(self):
        """Test chart data generation has correct structure"""
        self.client.force_login(self.user1)
        response = self.client.get(reverse("view_engineer", args=[self.user1.id]))
        context = response.context

        chart_data = context["chart_data"]
        self.assertIsInstance(chart_data, list)

        if len(chart_data) > 0:
            header = chart_data[0]
            self.assertEqual(header, ["Date", "S0", "S1", "S2", "S3", "Total"])

    def test_view_engineer_user_not_found(self):
        """Test handling of non-existent user ID"""
        self.client.force_login(self.superuser)
        response = self.client.get(reverse("view_engineer", args=[99999]))
        self.assertEqual(response.status_code, 404)

    @patch("django.utils.timezone.now")
    def test_view_engineer_empty_data(self, mock_now):
        """Test view behavior with user who has no findings"""
        fixed_now = timezone.make_aware(datetime(2023, 6, 15, 10, 0, 0))
        mock_now.return_value = fixed_now

        empty_user = User.objects.create(
            username="empty_user",
            email="empty@example.com",
            first_name="Empty",
            last_name="User",
        )

        self.client.force_login(self.superuser)
        response = self.client.get(reverse("view_engineer", args=[empty_user.id]))
        context = response.context

        # Should have zero values, not missing keys
        self.assertEqual(context["critical_open_month"], 0)
        self.assertEqual(context["high_open_month"], 0)
        self.assertEqual(context["lt"], 0)
        self.assertEqual(context["mn"], 0)

    def test_view_engineer_context_completeness(self):
        """Test that all expected context variables are present"""
        self.client.force_login(self.user1)
        response = self.client.get(reverse("view_engineer", args=[self.user1.id]))
        context = response.context

        # Test critical context keys exist
        required_keys = [
            "open_month", "a_month", "closed_month",
            "critical_open_month", "high_open_month", "medium_open_month", "low_open_month",
            "open_week_count", "closed_week_count",
            "lt", "ls", "ln", "mn",
            "chart_data", "name", "user",
        ]

        for key in required_keys:
            self.assertIn(key, context, f"Missing required context key: {key}")
