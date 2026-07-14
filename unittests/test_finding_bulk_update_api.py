"""
API tests for the bulk finding-update endpoint: ``PATCH /api/v2/findings/bulk/``.

The endpoint updates an allowlisted set of fields (EPSS / KEV threat-intelligence
metadata) on many findings in a single atomic transaction, with a per-item edit
permission check. These tests cover the happy path, input validation, the
per-request limit, atomic rollback on a permission failure, and that audit
history is recorded exactly as for a normal PATCH.
"""
import datetime

from django.apps import apps
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.finding.api.serializer import BULK_UPDATE_MAX_FINDINGS
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
)
from unittests.dojo_test_case import DojoAPITestCase

BULK_URL = "/api/v2/findings/bulk/"


class TestFindingBulkUpdateApi(DojoAPITestCase):

    @classmethod
    def setUpTestData(cls):
        start = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
        end = datetime.datetime(2020, 2, 1, tzinfo=datetime.UTC)

        # A non-staff user authorized on product_a only. Staff/superusers bypass
        # all object permissions, so a non-staff, scoped user is required to
        # exercise the per-item authorization path.
        cls.user = Dojo_User.objects.create(username="bulk_tester", is_staff=False)
        cls.token = Token.objects.create(user=cls.user)

        cls.test_type = Test_Type.objects.create(name="Bulk Update Mock Scan", static_tool=True)

        # Product the user is authorized to edit.
        cls.product_type_a = Product_Type.objects.create(name="Owned")
        cls.product_a = Product.objects.create(prod_type=cls.product_type_a, name="Owned Product", description="Owned")
        cls.product_a.authorized_users.add(cls.user)
        cls.engagement_a = Engagement.objects.create(product=cls.product_a, target_start=start, target_end=end)
        cls.test_a = Test.objects.create(engagement=cls.engagement_a, test_type=cls.test_type, target_start=start, target_end=end)

        # Product the user has no membership in (and therefore cannot edit).
        cls.product_type_b = Product_Type.objects.create(name="Foreign")
        cls.product_b = Product.objects.create(prod_type=cls.product_type_b, name="Foreign Product", description="Foreign")
        cls.engagement_b = Engagement.objects.create(product=cls.product_b, target_start=start, target_end=end)
        cls.test_b = Test.objects.create(engagement=cls.engagement_b, test_type=cls.test_type, target_start=start, target_end=end)

        cls.finding_1 = cls._create_finding(cls.test_a, "Finding One")
        cls.finding_2 = cls._create_finding(cls.test_a, "Finding Two")
        cls.foreign_finding = cls._create_finding(cls.test_b, "Foreign Finding")

    @classmethod
    def _create_finding(cls, test, title):
        return Finding.objects.create(
            test=test,
            title=title,
            severity="High",
            numerical_severity="S1",
            verified=False,
            active=True,
            description="desc",
            reporter=cls.user,
        )

    def setUp(self):
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + self.token.key)

    def _patch(self, findings):
        return self.client.patch(BULK_URL, data={"findings": findings}, format="json")

    # --- happy path -------------------------------------------------------

    def test_bulk_update_success(self):
        response = self._patch([
            {"id": self.finding_1.id, "epss_score": 0.42, "known_exploited": True},
            {"id": self.finding_2.id, "epss_percentile": 0.9, "kev_date": "2024-01-15"},
        ])
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content[:500])

        self.finding_1.refresh_from_db()
        self.finding_2.refresh_from_db()
        self.assertEqual(self.finding_1.epss_score, 0.42)
        self.assertTrue(self.finding_1.known_exploited)
        self.assertEqual(self.finding_2.epss_percentile, 0.9)
        self.assertEqual(self.finding_2.kev_date, datetime.date(2024, 1, 15))

    def test_bulk_update_response_lists_updated_findings(self):
        response = self._patch([
            {"id": self.finding_1.id, "epss_score": 0.1},
            {"id": self.finding_2.id, "epss_score": 0.2},
        ])
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content[:500])
        returned_ids = {finding["id"] for finding in response.json()}
        self.assertEqual(returned_ids, {self.finding_1.id, self.finding_2.id})

    def test_bulk_update_leaves_unlisted_fields_untouched(self):
        original_severity = self.finding_1.severity
        response = self._patch([{"id": self.finding_1.id, "epss_score": 0.33}])
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content[:500])
        self.finding_1.refresh_from_db()
        self.assertEqual(self.finding_1.severity, original_severity)

    # --- validation -------------------------------------------------------

    def test_unknown_field_rejected(self):
        response = self._patch([{"id": self.finding_1.id, "severity": "Critical"}])
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, response.content[:500])
        self.finding_1.refresh_from_db()
        self.assertEqual(self.finding_1.severity, "High")

    def test_unknown_finding_id_rejected(self):
        response = self._patch([{"id": 999999, "epss_score": 0.1}])
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, response.content[:500])

    def test_duplicate_id_rejected(self):
        response = self._patch([
            {"id": self.finding_1.id, "epss_score": 0.1},
            {"id": self.finding_1.id, "epss_score": 0.2},
        ])
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, response.content[:500])

    def test_item_without_updatable_fields_rejected(self):
        response = self._patch([{"id": self.finding_1.id}])
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, response.content[:500])

    def test_invalid_epss_score_rejected(self):
        response = self._patch([{"id": self.finding_1.id, "epss_score": 5}])
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, response.content[:500])
        self.finding_1.refresh_from_db()
        self.assertIsNone(self.finding_1.epss_score)

    def test_empty_findings_list_rejected(self):
        response = self._patch([])
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, response.content[:500])

    def test_over_limit_rejected(self):
        payload = [{"id": self.finding_1.id, "epss_score": 0.1} for _ in range(BULK_UPDATE_MAX_FINDINGS + 1)]
        response = self._patch(payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, response.content[:500])

    # --- authorization ----------------------------------------------------

    def test_forbidden_finding_fails_entire_batch(self):
        # finding_1 is editable, foreign_finding is not: the whole batch must be
        # rejected and finding_1 must remain unchanged (atomic rollback).
        response = self._patch([
            {"id": self.finding_1.id, "epss_score": 0.5},
            {"id": self.foreign_finding.id, "epss_score": 0.5},
        ])
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN, response.content[:500])
        self.finding_1.refresh_from_db()
        self.foreign_finding.refresh_from_db()
        self.assertIsNone(self.finding_1.epss_score)
        self.assertIsNone(self.foreign_finding.epss_score)

    def test_requires_authentication(self):
        anonymous = APIClient()
        response = anonymous.patch(BULK_URL, data={"findings": [{"id": self.finding_1.id, "epss_score": 0.1}]}, format="json")
        self.assertIn(response.status_code, (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN), response.content[:500])

    # --- audit history ----------------------------------------------------

    def test_bulk_update_records_audit_history(self):
        # A bulk update is a normal row UPDATE, so it fires the pghistory trigger
        # and produces an audit event exactly as a normal PATCH would. pghistory
        # triggers are enabled by default (ENABLE_AUDITLOG defaults to True), so
        # this only verifies the event is recorded.
        finding_event_model = apps.get_model("dojo", "FindingEvent")
        events_before = finding_event_model.objects.filter(pgh_obj_id=self.finding_1.id).count()

        response = self._patch([{"id": self.finding_1.id, "epss_score": 0.77}])
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content[:500])

        events_after = finding_event_model.objects.filter(pgh_obj_id=self.finding_1.id).count()
        self.assertGreater(events_after, events_before, "Expected a pghistory event after the bulk update")
        # The audit trail must capture the new value, exactly as for a normal PATCH.
        self.assertTrue(
            finding_event_model.objects.filter(pgh_obj_id=self.finding_1.id, epss_score=0.77).exists(),
            "Expected an audit event recording the updated epss_score",
        )
