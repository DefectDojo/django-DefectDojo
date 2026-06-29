"""
Authorization scoping for the bulk finding endpoint.

A product-scoped, non-staff user must not be able to bulk-delete (or edit)
findings belonging to products they are not authorized for via
``finding_bulk_update_all`` (``/finding/bulk``), even by POSTing arbitrary
finding ids.
"""

from django.urls import reverse

from dojo.models import Dojo_User, Finding, Test

from .dojo_test_case import DojoTestCase, versioned_fixtures


@versioned_fixtures
class TestBulkFindingAuthorizationScoping(DojoTestCase):

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.user = Dojo_User.objects.create(username="bulk_scoped", is_active=True)
        # The user is authorized on this product only (via authorized_users).
        self.product = Test.objects.get(id=3).engagement.product
        self.product.authorized_users.add(self.user)
        # A finding that belongs to a DIFFERENT product.
        self.other_finding = Finding.objects.exclude(
            test__engagement__product=self.product,
        ).first()
        self.assertIsNotNone(self.other_finding)
        self.client.force_login(self.user)

    def test_scoped_user_cannot_bulk_delete_other_products_findings(self):
        response = self.client.post(reverse("finding_bulk_update_all"), {
            "finding_to_update": [self.other_finding.id],
            "delete_bulk_findings": "1",
        })
        self.assertLess(response.status_code, 500)
        self.assertTrue(
            Finding.objects.filter(id=self.other_finding.id).exists(),
            msg="scoped user deleted a finding outside their authorized products",
        )

    def test_scoped_user_cannot_bulk_edit_other_products_findings(self):
        original_severity = self.other_finding.severity
        new_severity = "Low" if original_severity != "Low" else "High"
        response = self.client.post(reverse("finding_bulk_update_all"), {
            "finding_to_update": [self.other_finding.id],
            "severity": new_severity,
        })
        self.assertLess(response.status_code, 500)
        self.other_finding.refresh_from_db()
        self.assertEqual(
            self.other_finding.severity, original_severity,
            msg="scoped user edited a finding outside their authorized products",
        )
