import datetime

from django.contrib.auth.models import User
from django.contrib.messages import get_messages
from django.urls import reverse
from django.utils import timezone

from dojo.authorization.roles_permissions import Roles
from dojo.models import (
    Engagement,
    Finding,
    Product,
    Product_Type,
    Product_Type_Member,
    Role,
    Test,
    Test_Type,
)

from .dojo_test_case import DojoTestCase


class TestBulkEditValidation(DojoTestCase):

    """Test bulk edit validation rules for issue #11336"""

    @classmethod
    def setUpTestData(cls):
        # Create user with permissions
        cls.user = User(username="testuser", is_staff=True)
        cls.user.set_password("testpass")
        cls.user.save()

        # Create product type and product
        cls.product_type = Product_Type.objects.create(name="Web App")
        cls.product = Product.objects.create(
            prod_type=cls.product_type,
            name="Test Product",
            description="Test product for bulk edit validation",
        )
        # Give user owner role
        Product_Type_Member.objects.create(
            product_type=cls.product_type,
            user=cls.user,
            role=Role.objects.get(id=Roles.Owner),
        )

        # Create engagement and test
        cls.engagement = Engagement.objects.create(
            product=cls.product,
            target_start=timezone.now(),
            target_end=timezone.now() + datetime.timedelta(days=30),
        )
        cls.test_type = Test_Type.objects.create(
            name="Manual Test",
            static_tool=True,
        )
        cls.test = Test.objects.create(
            engagement=cls.engagement,
            test_type=cls.test_type,
            target_start=timezone.now(),
            target_end=timezone.now() + datetime.timedelta(days=1),
        )

        # Create findings in various states
        # Normal finding (not duplicate, not active)
        cls.normal_finding = Finding.objects.create(
            test=cls.test,
            title="Normal Finding",
            severity="High",
            active=False,
            verified=False,
            duplicate=False,
            reporter=cls.user,
            numerical_severity="S1",
        )

        # Duplicate finding (duplicate=True, active=False)
        cls.original_finding = Finding.objects.create(
            test=cls.test,
            title="Original Finding",
            severity="High",
            active=True,
            verified=True,
            duplicate=False,
            reporter=cls.user,
            numerical_severity="S1",
        )
        cls.duplicate_finding = Finding.objects.create(
            test=cls.test,
            title="Duplicate Finding",
            severity="High",
            active=False,
            verified=False,
            duplicate=True,
            duplicate_finding=cls.original_finding,
            reporter=cls.user,
            numerical_severity="S1",
        )

        # Active finding (active=True, not duplicate)
        cls.active_finding = Finding.objects.create(
            test=cls.test,
            title="Active Finding",
            severity="High",
            active=True,
            verified=True,
            duplicate=False,
            reporter=cls.user,
            numerical_severity="S1",
        )

        # Inactive finding (active=False, not duplicate)
        cls.inactive_finding = Finding.objects.create(
            test=cls.test,
            title="Inactive Finding",
            severity="High",
            active=False,
            verified=False,
            duplicate=False,
            reporter=cls.user,
            numerical_severity="S1",
        )

    def setUp(self):
        self.client.force_login(self.user)

    def _bulk_edit_post_data(self, finding_ids, **kwargs):
        """Helper to build POST data for bulk edit"""
        data = {
            "finding_to_update": [str(fid) for fid in finding_ids],
            "return_url": reverse("view_test", args=(self.test.id,)),
        }
        # Add status checkbox if any status fields are being set
        if any(
            key in kwargs
            for key in [
                "active",
                "verified",
                "false_p",
                "out_of_scope",
                "is_mitigated",
                "under_review",
            ]
        ):
            data["status"] = "on"

        # Add status fields
        if kwargs.get("active"):
            data["active"] = "on"
        if kwargs.get("verified"):
            data["verified"] = "on"
        if kwargs.get("false_p"):
            data["false_p"] = "on"
        if kwargs.get("out_of_scope"):
            data["out_of_scope"] = "on"
        if kwargs.get("is_mitigated"):
            data["is_mitigated"] = "on"
        if kwargs.get("under_review"):
            data["under_review"] = "on"
        if kwargs.get("duplicate"):
            data["duplicate"] = "on"

        # Add risk acceptance fields
        if kwargs.get("risk_acceptance"):
            data["risk_acceptance"] = "on"
        if kwargs.get("risk_accept"):
            data["risk_accept"] = "on"
        if kwargs.get("risk_unaccept"):
            data["risk_unaccept"] = "on"

        # Add other fields
        if "severity" in kwargs:
            data["severity"] = kwargs["severity"]
        if "date" in kwargs:
            data["date"] = kwargs["date"]

        return data

    def _assert_finding_status(self, finding, **expected_fields):
        """Helper to verify finding state"""
        finding.refresh_from_db()
        for field, expected_value in expected_fields.items():
            actual_value = getattr(finding, field)
            self.assertEqual(
                actual_value,
                expected_value,
                f"Finding {finding.id} field {field}: expected {expected_value}, got {actual_value}",
            )

    def _get_messages_text(self, response):
        """Helper to get all message texts from response"""
        # Django test client stores messages in the session
        # Try multiple methods to access them
        messages_list = []
        try:
            # Method 1: Try via wsgi_request if available
            if hasattr(response, "wsgi_request") and response.wsgi_request:
                messages_list = [str(m) for m in get_messages(response.wsgi_request)]
            # Method 2: Try via response.request._messages
            elif hasattr(response, "request") and hasattr(response.request, "_messages"):
                storage = response.request._messages
                messages_list = [str(m) for m in storage]
            # Method 3: Try via client session (Django test client stores messages here)
            elif hasattr(response, "client") and hasattr(response.client, "session"):
                # Messages are stored in the session
                # Create a mock request to access messages from session
                from django.test import RequestFactory  # noqa: PLC0415

                factory = RequestFactory()
                request = factory.get("/")
                request.session = response.client.session
                messages_list = [str(m) for m in get_messages(request)]
        except (AttributeError, TypeError, ImportError):
            # If messages aren't accessible, that's okay
            # Tests can still verify behavior by checking finding state
            pass
        return messages_list

    # Form Validation Tests

    def test_form_rejects_active_and_risk_accept_together(self):
        """Test that form validation rejects active + risk_accept"""
        from dojo.forms import FindingBulkUpdateForm  # noqa: PLC0415
        form_data = {
            "active": True,
            "risk_acceptance": True,
            "risk_accept": True,
            "severity": "",
            "verified": False,
            "false_p": False,
            "duplicate": False,
            "out_of_scope": False,
            "under_review": False,
            "is_mitigated": False,
        }
        form = FindingBulkUpdateForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("Active findings cannot be risk accepted", str(form.errors))

    def test_form_rejects_duplicate_and_active_together(self):
        """Test that form validation rejects duplicate + active"""
        from dojo.forms import FindingBulkUpdateForm  # noqa: PLC0415
        form_data = {
            "duplicate": True,
            "active": True,
            "severity": "",
            "verified": False,
            "false_p": False,
            "out_of_scope": False,
            "under_review": False,
            "is_mitigated": False,
        }
        form = FindingBulkUpdateForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("Duplicate findings cannot be verified or active", str(form.errors))

    def test_form_rejects_duplicate_and_verified_together(self):
        """Test that form validation rejects duplicate + verified"""
        from dojo.forms import FindingBulkUpdateForm  # noqa: PLC0415
        form_data = {
            "duplicate": True,
            "verified": True,
            "severity": "",
            "active": False,
            "false_p": False,
            "out_of_scope": False,
            "under_review": False,
            "is_mitigated": False,
        }
        form = FindingBulkUpdateForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn("Duplicate findings cannot be verified or active", str(form.errors))

    def test_form_allows_duplicate_with_other_fields(self):
        """Test that form allows duplicate with other non-conflicting fields"""
        from dojo.forms import FindingBulkUpdateForm  # noqa: PLC0415
        form_data = {
            "duplicate": True,
            "false_p": True,
            "out_of_scope": True,
            "severity": "",
            "active": False,
            "verified": False,
            "under_review": False,
            "is_mitigated": False,
        }
        form = FindingBulkUpdateForm(data=form_data)
        # Form should be valid (though it may have other validation issues)
        # The key is that duplicate + false_p + out_of_scope doesn't raise our specific error
        form_errors = str(form.errors) if not form.is_valid() else ""
        self.assertNotIn("Duplicate findings cannot be verified or active", form_errors)

    # View-Level Validation Tests (Duplicate Findings)

    def test_bulk_edit_duplicate_finding_cannot_set_active(self):
        """Test that duplicate findings cannot be set as active via bulk edit"""
        post_data = self._bulk_edit_post_data(
            [self.duplicate_finding.id],
            active=True,
            false_p=False,
            out_of_scope=False,
        )

        response = self.client.post(
            reverse("finding_bulk_update_all"),
            post_data,
            follow=True,
        )

        # Verify finding remains inactive
        self._assert_finding_status(
            self.duplicate_finding,
            active=False,
            duplicate=True,
        )
        # Verify other fields can still be updated
        # (We set false_p=False, so it should remain False)

        # Verify warning message
        messages = self._get_messages_text(response)
        warning_messages = [m for m in messages if "duplicate findings" in m.lower()]
        self.assertGreater(
            len(warning_messages),
            0,
            f"Expected warning about duplicate findings, got messages: {messages}",
        )
        self.assertIn("Skipped status update", warning_messages[0])

    def test_bulk_edit_duplicate_finding_cannot_set_verified(self):
        """Test that duplicate findings cannot be set as verified via bulk edit"""
        post_data = self._bulk_edit_post_data(
            [self.duplicate_finding.id],
            verified=True,
        )

        response = self.client.post(
            reverse("finding_bulk_update_all"),
            post_data,
            follow=True,
        )

        # Verify finding remains unverified
        self._assert_finding_status(
            self.duplicate_finding,
            verified=False,
            duplicate=True,
        )

        # Verify warning message
        messages = self._get_messages_text(response)
        warning_messages = [m for m in messages if "duplicate findings" in m.lower()]
        self.assertGreater(len(warning_messages), 0)

    def test_bulk_edit_duplicate_finding_can_update_other_fields(self):
        """Test that duplicate findings can update other status fields"""
        post_data = self._bulk_edit_post_data(
            [self.duplicate_finding.id],
            false_p=True,
            out_of_scope=True,
        )

        response = self.client.post(
            reverse("finding_bulk_update_all"),
            post_data,
            follow=True,
        )

        # Verify other fields are updated
        self._assert_finding_status(
            self.duplicate_finding,
            false_p=True,
            out_of_scope=True,
            duplicate=True,
            active=False,  # Should remain False
        )

        # Verify no warning about duplicates (no conflict)
        messages = self._get_messages_text(response)
        warning_messages = [m for m in messages if "duplicate findings" in m.lower()]
        self.assertEqual(
            len(warning_messages),
            0,
            f"Unexpected duplicate warning: {warning_messages}",
        )

    def test_bulk_edit_duplicate_finding_severity_update_works(self):
        """Test that severity can be updated on duplicate findings"""
        post_data = self._bulk_edit_post_data(
            [self.duplicate_finding.id],
            severity="Critical",
        )

        response = self.client.post(
            reverse("finding_bulk_update_all"),
            post_data,
            follow=True,
        )

        # Verify severity is updated
        self._assert_finding_status(
            self.duplicate_finding,
            severity="Critical",
            duplicate=True,
        )

        # Verify no validation errors
        self.assertNotEqual(response.status_code, 500)

    # View-Level Validation Tests (Active + Risk Acceptance)

    def test_bulk_edit_active_finding_can_accept_risk(self):
        """Test that active findings can accept risk via bulk edit (matching individual behavior)"""
        # Enable simple risk acceptance on product
        self.product.enable_simple_risk_acceptance = True
        self.product.save()

        post_data = self._bulk_edit_post_data(
            [self.active_finding.id],
            risk_acceptance=True,
            risk_accept=True,
        )

        response = self.client.post(
            reverse("finding_bulk_update_all"),
            post_data,
            follow=True,
        )

        # Verify finding IS risk accepted and becomes inactive
        self.active_finding.refresh_from_db()
        self.assertTrue(
            self.active_finding.risk_accepted,
            "Active finding should be risk accepted",
        )
        self.assertFalse(
            self.active_finding.active,
            "Risk accepted finding should become inactive",
        )

        # Verify no warning message about active findings
        messages = self._get_messages_text(response)
        warning_messages = [
            m for m in messages if "active findings" in m.lower() and "risk" in m.lower()
        ]
        self.assertEqual(
            len(warning_messages),
            0,
            f"Unexpected warning about active findings: {warning_messages}",
        )

    def test_bulk_edit_inactive_finding_can_accept_risk(self):
        """Test that inactive findings can accept risk"""
        # Enable simple risk acceptance on product
        self.product.enable_simple_risk_acceptance = True
        self.product.save()

        post_data = self._bulk_edit_post_data(
            [self.inactive_finding.id],
            risk_acceptance=True,
            risk_accept=True,
        )

        response = self.client.post(
            reverse("finding_bulk_update_all"),
            post_data,
            follow=True,
        )

        # Verify finding IS risk accepted
        self.inactive_finding.refresh_from_db()
        self.assertTrue(
            self.inactive_finding.risk_accepted,
            "Inactive finding should be risk accepted",
        )

        # Verify no warning about active findings
        messages = self._get_messages_text(response)
        warning_messages = [
            m for m in messages if "active findings" in m.lower() and "risk" in m.lower()
        ]
        self.assertEqual(
            len(warning_messages),
            0,
            f"Unexpected active findings warning: {warning_messages}",
        )

    def test_bulk_edit_duplicate_finding_can_accept_risk_if_not_active(self):
        """Test that duplicate but inactive findings can accept risk"""
        # Enable simple risk acceptance on product
        self.product.enable_simple_risk_acceptance = True
        self.product.save()

        post_data = self._bulk_edit_post_data(
            [self.duplicate_finding.id],
            risk_acceptance=True,
            risk_accept=True,
        )

        self.client.post(
            reverse("finding_bulk_update_all"),
            post_data,
            follow=True,
        )

        # Verify finding IS risk accepted (duplicate check happens first, then active check)
        self.duplicate_finding.refresh_from_db()
        self.assertTrue(
            self.duplicate_finding.risk_accepted,
            "Duplicate but inactive finding should be risk accepted",
        )

    # User Feedback Tests

    def test_bulk_edit_shows_success_message_with_actual_count(self):
        """Test that success message shows actually_updated_count"""
        # Create mix: 1 duplicate, 2 normal findings
        normal1 = Finding.objects.create(
            test=self.test,
            title="Normal 1",
            severity="High",
            active=False,
            reporter=self.user,
            numerical_severity="S1",
        )
        normal2 = Finding.objects.create(
            test=self.test,
            title="Normal 2",
            severity="High",
            active=False,
            reporter=self.user,
            numerical_severity="S1",
        )

        post_data = self._bulk_edit_post_data(
            [self.duplicate_finding.id, normal1.id, normal2.id],
            active=True,
        )

        response = self.client.post(
            reverse("finding_bulk_update_all"),
            post_data,
            follow=True,
        )

        # Verify success message
        messages = self._get_messages_text(response)
        success_messages = [m for m in messages if "successful" in m.lower()]
        self.assertGreater(len(success_messages), 0)

        # Verify warning about skipped duplicate
        warning_messages = [m for m in messages if "duplicate findings" in m.lower()]
        self.assertGreater(len(warning_messages), 0)

        # Verify normal findings were updated
        self._assert_finding_status(normal1, active=True)
        self._assert_finding_status(normal2, active=True)

    def test_bulk_edit_shows_multiple_warning_messages(self):
        """
        Test that warning messages appear for conflicts (duplicate status)
        and that active findings can now be risk accepted successfully
        """
        # Enable simple risk acceptance
        self.product.enable_simple_risk_acceptance = True
        self.product.save()

        # First, try to set duplicate finding as active (will be skipped with warning)
        post_data1 = self._bulk_edit_post_data(
            [self.duplicate_finding.id],
            active=True,  # Will conflict with duplicate
        )
        response1 = self.client.post(
            reverse("finding_bulk_update_all"),
            post_data1,
            follow=True,
        )

        # Then, risk accept active finding (should succeed - no longer a conflict)
        post_data2 = self._bulk_edit_post_data(
            [self.active_finding.id],
            risk_acceptance=True,
            risk_accept=True,  # Should work now!
        )
        response2 = self.client.post(
            reverse("finding_bulk_update_all"),
            post_data2,
            follow=True,
        )

        # Combine messages from both requests
        messages1 = self._get_messages_text(response1)
        messages2 = self._get_messages_text(response2)
        all_messages = messages1 + messages2

        # Verify duplicate warning appears
        duplicate_warnings = [
            m for m in all_messages if "duplicate findings" in m.lower()
        ]
        self.assertGreater(
            len(duplicate_warnings),
            0,
            f"Expected duplicate warning, got: {all_messages}",
        )

        # Verify NO warning about active findings and risk acceptance
        active_warnings = [
            m
            for m
            in all_messages
            if "active findings" in m.lower() and "risk" in m.lower()
        ]
        self.assertEqual(
            len(active_warnings),
            0,
            f"Unexpected active risk acceptance warning: {active_warnings}",
        )

        # Verify active finding was successfully risk accepted
        self.active_finding.refresh_from_db()
        self.assertTrue(
            self.active_finding.risk_accepted,
            "Active finding should be risk accepted successfully",
        )

    def test_bulk_edit_no_warning_when_no_conflicts(self):
        """Test that no warnings appear when there are no conflicts"""
        post_data = self._bulk_edit_post_data(
            [self.normal_finding.id],
            active=True,
            verified=True,
        )

        response = self.client.post(
            reverse("finding_bulk_update_all"),
            post_data,
            follow=True,
        )

        messages = self._get_messages_text(response)
        warning_messages = [
            m
            for m
            in messages
            if "duplicate" in m.lower() or ("active" in m.lower() and "risk" in m.lower())
        ]

        self.assertEqual(
            len(warning_messages),
            0,
            f"Unexpected warnings: {warning_messages}",
        )

        # Verify success message
        success_messages = [m for m in messages if "successful" in m.lower()]
        self.assertGreater(len(success_messages), 0)

    # Edge Cases

    def test_bulk_edit_mixed_findings_partial_success(self):
        """Test bulk edit with mix of duplicate and normal findings"""
        # Create 2 more normal findings
        normal1 = Finding.objects.create(
            test=self.test,
            title="Normal 1",
            severity="High",
            active=False,
            reporter=self.user,
            numerical_severity="S1",
        )
        normal2 = Finding.objects.create(
            test=self.test,
            title="Normal 2",
            severity="High",
            active=False,
            reporter=self.user,
            numerical_severity="S1",
        )
        normal3 = Finding.objects.create(
            test=self.test,
            title="Normal 3",
            severity="High",
            active=False,
            reporter=self.user,
            numerical_severity="S1",
        )

        post_data = self._bulk_edit_post_data(
            [
                self.duplicate_finding.id,
                self.duplicate_finding.id,  # Add same duplicate twice to test
                normal1.id,
                normal2.id,
                normal3.id,
            ],
            active=True,
        )

        response = self.client.post(
            reverse("finding_bulk_update_all"),
            post_data,
            follow=True,
        )

        # Verify normal findings were updated
        self._assert_finding_status(normal1, active=True)
        self._assert_finding_status(normal2, active=True)
        self._assert_finding_status(normal3, active=True)

        # Verify duplicate findings remain inactive
        self._assert_finding_status(self.duplicate_finding, active=False, duplicate=True)

        # Verify warning message shows skipped count
        messages = self._get_messages_text(response)
        warning_messages = [m for m in messages if "duplicate findings" in m.lower()]
        self.assertGreater(len(warning_messages), 0)

    def test_bulk_edit_severity_only_no_status_conflicts(self):
        """Test that severity-only updates work regardless of duplicate status"""
        post_data = self._bulk_edit_post_data(
            [self.duplicate_finding.id],
            severity="Critical",
        )

        response = self.client.post(
            reverse("finding_bulk_update_all"),
            post_data,
            follow=True,
        )

        # Verify severity is updated
        self._assert_finding_status(
            self.duplicate_finding,
            severity="Critical",
            duplicate=True,
        )

        # Verify no validation errors or warnings
        messages = self._get_messages_text(response)
        warning_messages = [m for m in messages if "duplicate" in m.lower()]
        self.assertEqual(len(warning_messages), 0)

    def test_bulk_edit_date_update_works_regardless_of_duplicate_status(self):
        """Test that date updates work regardless of duplicate status"""
        new_date = timezone.now().date()
        post_data = self._bulk_edit_post_data(
            [self.duplicate_finding.id],
            date=new_date,
        )

        response = self.client.post(
            reverse("finding_bulk_update_all"),
            post_data,
            follow=True,
        )

        # Verify date is updated
        self.duplicate_finding.refresh_from_db()
        self.assertEqual(self.duplicate_finding.date, new_date)

        # Verify no validation errors
        self.assertNotEqual(response.status_code, 500)
