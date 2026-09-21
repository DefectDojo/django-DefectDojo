"""
Authorization scoping for the bulk finding endpoint.

A product-scoped, non-staff user must not be able to bulk-delete (or edit)
findings belonging to products they are not authorized for via
``finding_bulk_update_all`` (``/finding/bulk``), even by POSTing arbitrary
finding ids. The same scoping applies to the target finding group when adding
findings to a group.
"""

from django.urls import reverse

from dojo.authorization.authorization import user_has_permission
from dojo.models import Dojo_User, Finding, Finding_Group, Test

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

    def test_scoped_user_cannot_add_finding_to_other_products_group(self):
        # A finding the user is allowed to edit, in their authorized product,
        # not yet part of any group.
        my_finding = Finding.objects.filter(
            test__engagement__product=self.product,
            finding_group__isnull=True,
        ).first()
        self.assertIsNotNone(my_finding)
        # A group that belongs to a different product.
        other_test = Test.objects.exclude(
            engagement__product=self.product,
        ).first()
        other_group = Finding_Group.objects.create(
            name="scoping_regression_group", test=other_test, creator=self.user,
        )
        response = self.client.post(reverse("finding_bulk_update_all"), {
            "finding_to_update": [my_finding.id],
            "finding_group_add": "true",
            "add_to_finding_group_id": other_group.id,
        })
        self.assertLess(response.status_code, 500)
        self.assertNotIn(
            my_finding.id,
            list(other_group.findings.values_list("id", flat=True)),
            msg="scoped user added a finding to a group outside their authorized products",
        )


@versioned_fixtures
class TestBulkFindingDeleteRequiresStaff(DojoTestCase):

    """
    The bulk route must apply the same staff-only delete policy the single
    delete view applies. Product membership alone authorizes viewing and
    editing a finding, not deleting it.
    """

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.product = Test.objects.get(id=3).engagement.product
        self.finding = Finding.objects.filter(
            test__engagement__product=self.product,
        ).first()
        self.assertIsNotNone(self.finding)

    def _bulk_delete_as(self, user):
        self.product.authorized_users.add(user)
        self.client.force_login(user)
        response = self.client.post(reverse("finding_bulk_update_all"), {
            "finding_to_update": [self.finding.id],
            "delete_bulk_findings": "1",
        })
        self.assertLess(response.status_code, 500)
        return Finding.objects.filter(id=self.finding.id).exists()

    def test_member_cannot_bulk_delete_findings_in_their_own_product(self):
        member = Dojo_User.objects.create(
            username="bulk_delete_member", is_active=True, is_staff=False,
        )
        self.product.authorized_users.add(member)
        self.assertTrue(user_has_permission(member, self.finding, "edit"))
        self.assertFalse(user_has_permission(member, self.finding, "delete"))
        self.assertTrue(
            self._bulk_delete_as(member),
            msg="non-staff member deleted a finding the single delete view denies them",
        )

    def test_staff_can_still_bulk_delete_findings(self):
        staff = Dojo_User.objects.create(
            username="bulk_delete_staff", is_active=True, is_staff=True,
        )
        self.assertFalse(self._bulk_delete_as(staff))


@versioned_fixtures
class TestFindingGroupTestInvariant(DojoTestCase):

    """
    A finding group holds findings from its own test only, and the group page
    shows a viewer the members they are authorized for. A group whose members
    span two tests would otherwise hand every viewer of the anchor product the
    findings of the other one.
    """

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.my_test = Test.objects.get(id=3)
        self.my_product = self.my_test.engagement.product
        self.other_finding = Finding.objects.exclude(
            test__engagement__product=self.my_product,
        ).first()
        self.assertIsNotNone(self.other_finding)
        self.my_finding = Finding.objects.filter(
            test=self.my_test, finding_group__isnull=True,
        ).first()
        self.assertIsNotNone(self.my_finding)

    def test_bulk_create_does_not_group_findings_from_another_test(self):
        user = Dojo_User.objects.create(username="group_invariant", is_active=True)
        self.my_product.authorized_users.add(user)
        self.other_finding.test.engagement.product.authorized_users.add(user)
        self.client.force_login(user)

        response = self.client.post(reverse("finding_bulk_update_all"), {
            "finding_to_update": [self.my_finding.id, self.other_finding.id],
            "finding_group_create": "true",
            "finding_group_create_name": "invariant_regression_group",
        })
        self.assertLess(response.status_code, 500)

        group = Finding_Group.objects.filter(name="invariant_regression_group").first()
        self.assertIsNotNone(group)
        member_ids = list(group.findings.values_list("id", flat=True))
        self.assertIn(self.my_finding.id, member_ids)
        self.assertNotIn(
            self.other_finding.id, member_ids,
            msg="a finding from another test was grouped with the anchor test's findings",
        )

    def test_group_page_hides_members_the_viewer_cannot_access(self):
        viewer = Dojo_User.objects.create(username="group_viewer", is_active=True)
        self.my_product.authorized_users.add(viewer)
        group = Finding_Group.objects.create(
            name="invariant_display_group", test=self.my_test, creator=viewer,
        )
        group.findings.add(self.my_finding, self.other_finding)

        self.client.force_login(viewer)

        response = self.client.get(reverse("view_finding_group", args=(group.id,)))
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        self.assertIn(self.my_finding.title, body)
        self.assertNotIn(
            self.other_finding.title, body,
            msg="the group page disclosed a finding outside the viewer's authorized products",
        )
