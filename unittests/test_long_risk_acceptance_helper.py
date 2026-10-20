import logging
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

from dateutil.relativedelta import relativedelta
from django.db.models import Q, QuerySet
from django.utils import timezone
from django.test import TestCase

from dojo.api_v2.long_risk_acceptance.models import (
    RiskAcceptanceEngagement,
    RiskAcceptanceExclusionRule,
)
from dojo.api_v2.long_risk_acceptance import helper as helper_ra_engagement
from dojo.models import Finding, Notes, Product, Engagement, Dojo_User, Note_Type
from unittests.dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)


class ParseFilterValuesTestCase(TestCase):
    """Test cases for parse_filter_values function."""

    def test_parse_empty_string(self):
        """Test parsing empty string."""
        result = helper_ra_engagement.parse_filter_values("")
        self.assertEqual([], result)

    def test_parse_none(self):
        """Test parsing None."""
        result = helper_ra_engagement.parse_filter_values(None)
        self.assertEqual([], result)

    def test_parse_single_value(self):
        """Test parsing single value."""
        result = helper_ra_engagement.parse_filter_values("value1")
        self.assertEqual(["value1"], result)

    def test_parse_multiple_values(self):
        """Test parsing multiple comma-separated values."""
        result = helper_ra_engagement.parse_filter_values("value1,value2,value3")
        self.assertEqual(["value1", "value2", "value3"], result)

    def test_parse_values_with_spaces(self):
        """Test parsing values with spaces."""
        result = helper_ra_engagement.parse_filter_values("value1 , value2 , value3")
        self.assertEqual(["value1", "value2", "value3"], result)

    def test_parse_values_with_empty_elements(self):
        """Test parsing values with empty elements."""
        result = helper_ra_engagement.parse_filter_values("value1,,value2")
        self.assertEqual(["value1", "value2"], result)


class ApplyDynamicFilterTestCase(DojoTestCase):
    """Test cases for apply_dynamic_filter function."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.finding1 = Finding.objects.first()
        self.query = Finding.objects.all()

    def test_apply_filter_with_no_values(self):
        """Test applying filter with no values."""
        result = helper_ra_engagement.apply_dynamic_filter(
            self.query, "severity", ""
        )
        self.assertEqual(len(result), len(self.query))

    def test_apply_filter_with_single_value(self):
        """Test applying filter with single value."""
        if self.finding1:
            severity = self.finding1.severity
            result = helper_ra_engagement.apply_dynamic_filter(
                self.query, "severity", severity
            )
            self.assertGreater(len(result), 0)

    def test_apply_filter_with_multiple_values(self):
        """Test applying filter with multiple values."""
        result = helper_ra_engagement.apply_dynamic_filter(
            self.query, "severity", "Critical,High"
        )
        self.assertIsNotNone(result)


class AddNoteTestCase(DojoTestCase):
    """Test cases for add_note function."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.product = Product.objects.first()
        self.user = self.get_test_admin()
        self.ra_engagement = RiskAcceptanceEngagement.objects.create(
            product=self.product,
            owner=self.user,
        )

    def test_add_note_to_ra_engagement(self):
        """Test adding note to risk acceptance engagement."""
        note = helper_ra_engagement.add_note(
            "Test Event",
            self.ra_engagement,
            self.user,
        )
        self.assertIsNotNone(note)
        self.assertEqual(note.entry, f"Test Event: {self.ra_engagement.id}")
        self.assertEqual(note.author, self.user)
        self.assertIn(note, self.ra_engagement.notes.all())

    def test_add_note_multiple_calls(self):
        """Test adding multiple notes to the same engagement."""
        note1 = helper_ra_engagement.add_note(
            "Event 1",
            self.ra_engagement,
            self.user,
        )
        note2 = helper_ra_engagement.add_note(
            "Event 2",
            self.ra_engagement,
            self.user,
        )
        self.assertIsNotNone(note1)
        self.assertIsNotNone(note2)
        self.assertNotEqual(note1.id, note2.id)
        notes_in_engagement = list(self.ra_engagement.notes.all())
        self.assertIn(note1, notes_in_engagement)
        self.assertIn(note2, notes_in_engagement)
        self.assertEqual(len(notes_in_engagement), 2)

    def test_add_note_with_different_events(self):
        """Test adding notes with different event types."""
        events = [
            "Long Risk Acceptance Reviewed",
            "Long Risk Acceptance Accepted",
            "Long Risk Acceptance Rejected",
        ]
        notes = []
        for event in events:
            note = helper_ra_engagement.add_note(
                event,
                self.ra_engagement,
                self.user,
            )
            notes.append(note)
        
        for i, event in enumerate(events):
            self.assertIn(event, notes[i].entry)


class ApplyReviewTestCase(DojoTestCase):
    """Test cases for apply_review function."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.product = Product.objects.first()
        self.user = self.get_test_admin()
        self.ra_engagement = RiskAcceptanceEngagement.objects.create(
            product=self.product,
            owner=self.user,
            risk_status="Risks Pending",
        )
        self.request = Mock()
        self.request.user = self.user

    def test_apply_review_changes_status(self):
        """Test that apply_review changes risk status."""
        self.assertEqual(self.ra_engagement.risk_status, "Risks Pending")
        helper_ra_engagement.apply_review(self.request, self.ra_engagement)
        self.ra_engagement.refresh_from_db()
        self.assertEqual(self.ra_engagement.risk_status, "Risks Reviewed")

    def test_apply_review_sets_reviewed_by(self):
        """Test that apply_review sets reviewed_by."""
        helper_ra_engagement.apply_review(self.request, self.ra_engagement)
        self.ra_engagement.refresh_from_db()
        self.assertEqual(self.ra_engagement.reviewed_by, self.user.username)

    def test_apply_review_sets_reviewed_date(self):
        """Test that apply_review sets reviewed_date."""
        before = timezone.now()
        helper_ra_engagement.apply_review(self.request, self.ra_engagement)
        after = timezone.now()
        self.ra_engagement.refresh_from_db()
        self.assertIsNotNone(self.ra_engagement.reviewed_date)
        self.assertGreaterEqual(self.ra_engagement.reviewed_date, before)
        self.assertLessEqual(self.ra_engagement.reviewed_date, after)


class ActiveFindingsLongRiskAcceptanceTestCase(DojoTestCase):
    """Test cases for active_findings_long_risk_acceptance function."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.product = Product.objects.first()
        self.user = self.get_test_admin()

    def test_activate_findings(self):
        """Test activating findings."""
        findings = Finding.objects.all()[:3]
        # Deactivate findings first
        for finding in findings:
            finding.active = False
            finding.risk_accepted = True
            finding.risk_status = "Risk Accepted"
            finding.save()

        finding_qs = Finding.objects.filter(id__in=[f.id for f in findings])
        helper_ra_engagement.active_findings_long_risk_acceptance(finding_qs)

        for finding in findings:
            finding.refresh_from_db()
            self.assertTrue(finding.active)
            self.assertFalse(finding.risk_accepted)
            self.assertEqual(finding.risk_status, "Risk Active")

    def test_remove_tag_from_findings(self):
        """Test removing long_term_risk_acceptance tag from findings."""
        findings = Finding.objects.all()[:2]
        for finding in findings:
            finding.tags.add("long_term_risk_acceptance")
            finding.active = False
            finding.risk_accepted = True
            finding.save()

        finding_qs = Finding.objects.filter(id__in=[f.id for f in findings])
        helper_ra_engagement.active_findings_long_risk_acceptance(finding_qs)

        for finding in findings:
            finding.refresh_from_db()
            self.assertNotIn("long_term_risk_acceptance", finding.tags.all())


class AcceptFindingsTestCase(DojoTestCase):
    """Test cases for _accept_findings function."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.ra_engagement = RiskAcceptanceEngagement.objects.create(
            product=Product.objects.first(),
            owner=self.get_test_admin(),
            risk_status="Risks Pending",
        )

    def test_accept_findings(self):
        """Test accepting findings."""
        findings = Finding.objects.all()[:3]
        for finding in findings:
            finding.active = True
            finding.risk_accepted = False
            finding.risk_status = "Risk Active"
            finding.save()

        finding_qs = Finding.objects.filter(id__in=[f.id for f in findings])
        helper_ra_engagement._accept_findings(finding_qs, self.ra_engagement)

        for finding in findings:
            finding.refresh_from_db()
            self.assertFalse(finding.active)
            self.assertTrue(finding.risk_accepted)
            self.assertEqual(finding.risk_status, "Risk Accepted")

    def test_add_tag_to_findings(self):
        """Test adding long_term_risk_acceptance tag to findings."""
        findings = Finding.objects.all()[:2]
        finding_qs = Finding.objects.filter(id__in=[f.id for f in findings])
        helper_ra_engagement._accept_findings(finding_qs, self.ra_engagement)

        for finding in findings:
            finding.refresh_from_db()
            self.assertIn("long_term_risk_acceptance", finding.tags.values_list("name", flat=True))


class UpdateRaEngagementTestCase(DojoTestCase):
    """Test cases for _update_ra_engagement function."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.product = Product.objects.first()
        self.user = self.get_test_admin()
        self.ra_engagement = RiskAcceptanceEngagement.objects.create(
            product=self.product,
            owner=self.user,
            risk_status="Risks Pending",
        )

    def test_update_single_field(self):
        """Test updating single field."""
        update_fields = {"risk_status": "Risks Reviewed"}
        helper_ra_engagement._update_ra_engagement(self.ra_engagement, update_fields)
        self.ra_engagement.refresh_from_db()
        self.assertEqual(self.ra_engagement.risk_status, "Risks Reviewed")

    def test_update_multiple_fields(self):
        """Test updating multiple fields."""
        now = timezone.now()
        update_fields = {
            "risk_status": "Risks Reviewed",
            "reviewed_by": "Test User",
            "reviewed_date": now,
        }
        helper_ra_engagement._update_ra_engagement(self.ra_engagement, update_fields)
        self.ra_engagement.refresh_from_db()
        self.assertEqual(self.ra_engagement.risk_status, "Risks Reviewed")
        self.assertEqual(self.ra_engagement.reviewed_by, "Test User")
        self.assertEqual(self.ra_engagement.reviewed_date, now)


class GetExpiredLongRiskAcceptanceTestCase(DojoTestCase):
    """Test cases for get_expired_long_risk_acceptance_to_handle function."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.product = Product.objects.first()
        self.user = self.get_test_admin()

    def test_get_expired_acceptances(self):
        """Test getting expired risk acceptances."""
        # Create expired risk acceptance
        expired_date = timezone.now() - timedelta(days=1)
        ra_engagement = RiskAcceptanceEngagement.objects.create(
            product=self.product,
            owner=self.user,
            expiration_date=expired_date,
            expiration_date_handled=None,
        )

        result = helper_ra_engagement.get_expired_long_risk_acceptance_to_handle()
        self.assertIn(ra_engagement, result)

    def test_exclude_non_expired_acceptances(self):
        """Test that non-expired acceptances are not included."""
        # Create non-expired risk acceptance
        future_date = timezone.now() + timedelta(days=10)
        ra_engagement = RiskAcceptanceEngagement.objects.create(
            product=self.product,
            owner=self.user,
            expiration_date=future_date,
            expiration_date_handled=None,
        )

        result = helper_ra_engagement.get_expired_long_risk_acceptance_to_handle()
        self.assertNotIn(ra_engagement, result)

    def test_exclude_already_handled_acceptances(self):
        """Test that already handled acceptances are not included."""
        expired_date = timezone.now() - timedelta(days=1)
        ra_engagement = RiskAcceptanceEngagement.objects.create(
            product=self.product,
            owner=self.user,
            expiration_date=expired_date,
            expiration_date_handled=timezone.now(),
        )

        result = helper_ra_engagement.get_expired_long_risk_acceptance_to_handle()
        self.assertNotIn(ra_engagement, result)


class GetAlmostExpiredLongRiskAcceptanceTestCase(DojoTestCase):
    """Test cases for get_almost_expired_long_risk_acceptance_to_handle function."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.product = Product.objects.first()
        self.user = self.get_test_admin()

    def test_get_almost_expired_within_heads_up_days(self):
        """Test getting almost expired risk acceptances within heads up days."""
        heads_up_days = 5
        almost_expired_date = timezone.now().date() + timedelta(days=3)
        ra_engagement = RiskAcceptanceEngagement.objects.create(
            product=self.product,
            owner=self.user,
            expiration_date=timezone.make_aware(datetime.combine(almost_expired_date, datetime.min.time())),
            expiration_date_warned=None,
            expiration_date_handled=None,
        )

        result = helper_ra_engagement.get_almost_expired_long_risk_acceptance_to_handle(
            heads_up_days
        )
        self.assertIn(ra_engagement, result)

    def test_exclude_already_warned_acceptances(self):
        """Test that already warned acceptances are not included."""
        heads_up_days = 5
        almost_expired_date = timezone.now().date() + timedelta(days=3)
        ra_engagement = RiskAcceptanceEngagement.objects.create(
            product=self.product,
            owner=self.user,
            expiration_date=timezone.make_aware(datetime.combine(almost_expired_date, datetime.min.time())),
            expiration_date_warned=timezone.now(),
            expiration_date_handled=None,
        )

        result = helper_ra_engagement.get_almost_expired_long_risk_acceptance_to_handle(
            heads_up_days
        )
        self.assertNotIn(ra_engagement, result)

    def test_exclude_outside_heads_up_days(self):
        """Test that acceptances outside heads up days are not included."""
        heads_up_days = 5
        too_far_date = timezone.now().date() + timedelta(days=10)
        ra_engagement = RiskAcceptanceEngagement.objects.create(
            product=self.product,
            owner=self.user,
            expiration_date=timezone.make_aware(datetime.combine(too_far_date, datetime.min.time())),
            expiration_date_warned=None,
            expiration_date_handled=None,
        )

        result = helper_ra_engagement.get_almost_expired_long_risk_acceptance_to_handle(
            heads_up_days
        )
        self.assertNotIn(ra_engagement, result)


class HandleRejectTestCase(DojoTestCase):
    """Test cases for _handle_reject function."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.product = Product.objects.first()
        self.user = self.get_test_admin()
        self.ra_engagement = RiskAcceptanceEngagement.objects.create(
            product=self.product,
            owner=self.user,
            risk_status="Risks Accepted",
        )
        self.findings = Finding.objects.all()[:2]
        for finding in self.findings:
            finding.active = False
            finding.risk_accepted = True
            finding.save()
        self.finding_qs = Finding.objects.filter(id__in=[f.id for f in self.findings])

    @patch("dojo.api_v2.long_risk_acceptance.helper.Notification")
    def test_handle_reject(self, mock_notification):
        """Test handling reject event."""
        helper_ra_engagement._handle_reject(self.ra_engagement, self.user, self.finding_qs)

        self.ra_engagement.refresh_from_db()
        self.assertEqual(self.ra_engagement.risk_status, "Risks Rejected")

        for finding in self.findings:
            finding.refresh_from_db()
            self.assertTrue(finding.active)
            self.assertFalse(finding.risk_accepted)

        mock_notification.risk_acceptance_rejected.assert_called_once()


class HandleExpireTestCase(DojoTestCase):
    """Test cases for _handle_expire function."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.product = Product.objects.first()
        self.user = self.get_test_admin()
        self.ra_engagement = RiskAcceptanceEngagement.objects.create(
            product=self.product,
            owner=self.user,
            risk_status="Risks Accepted",
        )
        self.findings = Finding.objects.all()[:2]
        for finding in self.findings:
            finding.active = False
            finding.risk_accepted = True
            finding.save()
        self.finding_qs = Finding.objects.filter(id__in=[f.id for f in self.findings])

    @patch("dojo.api_v2.long_risk_acceptance.helper.Notification")
    def test_handle_expire(self, mock_notification):
        """Test handling expire event."""
        helper_ra_engagement._handle_expire(self.ra_engagement, self.user, self.finding_qs)

        self.ra_engagement.refresh_from_db()
        self.assertEqual(self.ra_engagement.risk_status, "Risks Expired")

        for finding in self.findings:
            finding.refresh_from_db()
            self.assertTrue(finding.active)
            self.assertFalse(finding.risk_accepted)

        mock_notification.risk_acceptance_expiration.assert_called_once()


class HandleAcceptTestCase(DojoTestCase):
    """Test cases for _handle_accept function."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.product = Product.objects.first()
        self.user = self.get_test_admin()
        self.ra_engagement = RiskAcceptanceEngagement.objects.create(
            product=self.product,
            owner=self.user,
            risk_status="Risks Reviewed",
        )
        self.findings = Finding.objects.all()[:2]
        for finding in self.findings:
            finding.active = True
            finding.risk_accepted = False
            finding.save()
        self.finding_qs = Finding.objects.filter(id__in=[f.id for f in self.findings])

    @patch("dojo.api_v2.long_risk_acceptance.helper.Notification")
    def test_handle_accept_success(self, mock_notification):
        """Test successful handling of accept event."""
        result = helper_ra_engagement._handle_accept(
            self.ra_engagement, self.user, self.finding_qs
        )
        self.assertTrue(result)

        self.ra_engagement.refresh_from_db()
        self.assertEqual(self.ra_engagement.risk_status, "Risks Accepted")

        for finding in self.findings:
            finding.refresh_from_db()
            self.assertFalse(finding.active)
            self.assertTrue(finding.risk_accepted)

    def test_handle_accept_invalid_status(self):
        """Test handling accept when status is invalid."""
        self.ra_engagement.risk_status = "Risks Pending"
        self.ra_engagement.save()

        result = helper_ra_engagement._handle_accept(
            self.ra_engagement, self.user, self.finding_qs
        )
        self.assertFalse(result)


class HandleReviewTestCase(DojoTestCase):
    """Test cases for _handle_review function."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.product = Product.objects.first()
        self.user = self.get_test_admin()
        self.ra_engagement = RiskAcceptanceEngagement.objects.create(
            product=self.product,
            owner=self.user,
            risk_status="Risks Pending",
        )

    @patch("dojo.api_v2.long_risk_acceptance.helper.Notification")
    def test_handle_review(self, mock_notification):
        """Test handling review event."""
        helper_ra_engagement._handle_review(self.ra_engagement, self.user)

        self.ra_engagement.refresh_from_db()
        self.assertEqual(self.ra_engagement.risk_status, "Risks Reviewed")
        self.assertEqual(self.ra_engagement.reviewed_by, self.user.username)
        self.assertIsNotNone(self.ra_engagement.reviewed_date)

        mock_notification.risk_acceptance_review.assert_called_once()


class RenderRuleTestCase(DojoTestCase):
    """Test cases for render_rule function."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.product = Product.objects.first()
        self.user = self.get_test_admin()
        self.engagement = Engagement.objects.first()
        self.ra_engagement = RiskAcceptanceEngagement.objects.create(
            product=self.product,
            owner=self.user,
        )

    def test_render_rule_no_rules(self):
        """Test rendering rule when no rules exist."""
        result = helper_ra_engagement.render_rule(self.ra_engagement, reverse_query=False)
        self.assertIsNone(result)

    def test_render_rule_empty_findings(self):
        """Test rendering rule with engagement that has no active findings."""
        # This test depends on the engagement having active findings
        result = helper_ra_engagement.render_rule(self.ra_engagement, reverse_query=False)
        # Should return QuerySet or None
        self.assertTrue(result is None or isinstance(result, QuerySet))


class ToExecuteRuleTestCase(DojoTestCase):
    """Test cases for to_execute_rule function."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.query = Finding.objects.all()

    def test_execute_rule_no_rules(self):
        """Test executing rules with empty rules list."""
        result = helper_ra_engagement.to_execute_rule(self.query, [], reverse_query=False)
        self.assertEqual(list(result), list(self.query))

    def test_execute_rule_with_empty_rule(self):
        """Test executing rules with empty rule."""
        rules = [None]
        result = helper_ra_engagement.to_execute_rule(self.query, rules, reverse_query=False)
        self.assertEqual(list(result), list(self.query))

    def test_execute_rule_with_filters(self):
        """Test executing rules with filters."""
        rule = Mock()
        rule.filters = {"severity": "Critical"}
        rule.exclusions = None
        rules = [rule]

        result = helper_ra_engagement.to_execute_rule(self.query, rules, reverse_query=False)
        self.assertIsNotNone(result)


class RiskAcceptanceEngagementModelTestCase(DojoTestCase):
    """Test cases for RiskAcceptanceEngagement model."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.product = Product.objects.first()
        self.user = self.get_test_admin()

    def test_add_note_to_model(self):
        """Test RiskAcceptanceEngagement.add_note method."""
        ra_engagement = RiskAcceptanceEngagement.objects.create(
            product=self.product,
            owner=self.user,
        )
        
        note_type = Note_Type.objects.create(
            name="Approval Test Model",
            description="Test approval type for model"
        )

        note = ra_engagement.add_note(
            "Test note",
            self.user,
            note_type=note_type,
            private=True,
        )

        self.assertIsNotNone(note)
        self.assertEqual(note.entry, "Test note")
        self.assertEqual(note.author, self.user)
        self.assertEqual(note.note_type, note_type)
        self.assertTrue(note.private)
        self.assertIn(note, ra_engagement.notes.all())

    def test_add_note_to_model_without_type(self):
        """Test RiskAcceptanceEngagement.add_note method without note type."""
        ra_engagement = RiskAcceptanceEngagement.objects.create(
            product=self.product,
            owner=self.user,
        )

        note = ra_engagement.add_note(
            "Test note without type",
            self.user,
        )

        self.assertIsNotNone(note)
        self.assertEqual(note.entry, "Test note without type")
        self.assertEqual(note.author, self.user)
        self.assertIsNone(note.note_type)
        self.assertFalse(note.private)
        self.assertIn(note, ra_engagement.notes.all())

    def test_risk_acceptance_engagement_creation(self):
        """Test creating a RiskAcceptanceEngagement."""
        ra_engagement = RiskAcceptanceEngagement.objects.create(
            product=self.product,
            owner=self.user,
            risk_status="Risks Pending",
            accepted_by="Test Acceptor",
            description="Test Description",
        )

        self.assertEqual(ra_engagement.product, self.product)
        self.assertEqual(ra_engagement.owner, self.user)
        self.assertEqual(ra_engagement.risk_status, "Risks Pending")
        self.assertEqual(ra_engagement.accepted_by, "Test Acceptor")

    def test_risk_acceptance_engagement_status_choices(self):
        """Test RiskAcceptanceEngagement status choices."""
        choices = dict(RiskAcceptanceEngagement.STATUS_CHOICES)
        expected_statuses = [
            "Risks Active",
            "Risks Reviewed",
            "Risks Pending",
            "Risks Accepted",
            "Risks Rejected",
            "Risks Expired",
        ]
        for status in expected_statuses:
            self.assertIn(status, choices)
