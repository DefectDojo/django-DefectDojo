"""
Regression tests for reference-scoped writes on a shared Location.

A Location row is deduplicated globally, so any product that records the same URL
references the same row. Authorization for the row therefore follows from a reference
the caller can create for themselves. A rename or a delete must act on the caller's own
reference, never on the shared row, or one product silently rewrites or destroys
another product's endpoint.
"""
from datetime import UTC, date, datetime

from django.urls import reverse

from dojo.authorization.models import Product_Member, Role
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.location.queries import remove_location_references
from dojo.models import Dojo_User, Engagement, Finding, Product, Product_Type, Test, Test_Type
from dojo.url.models import URL

from .dojo_test_case import DojoTestCase, skip_unless_v3
from .test_permissions_audit import LegacyAuthMirrorMixin

PASSWORD = "testTEST1234!@#$"
SHARED_HOST = "shared-writes.example.test"
OWN_HOST = "own-writes.example.test"


@skip_unless_v3
class TestLocationReferenceScopedWrites(LegacyAuthMirrorMixin, DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        cls.pt_mine = Product_Type.objects.create(name="Ref Scoped Mine PT")
        cls.pt_outside = Product_Type.objects.create(name="Ref Scoped Outside PT")
        cls.product_mine = Product.objects.create(
            name="Ref Scoped Mine Product", description="mine", prod_type=cls.pt_mine,
        )
        cls.product_outside = Product.objects.create(
            name="Ref Scoped Outside Product", description="out", prod_type=cls.pt_outside,
        )
        cls.user = Dojo_User.objects.create_user(
            username="ref_scoped_user", password=PASSWORD, is_active=True,
        )
        # Membership on the caller's product only.
        Product_Member.objects.create(
            product=cls.product_mine, user=cls.user, role=Role.objects.get(name="Owner"),
        )

        # One deduplicated Location that both products record.
        cls.shared = URL.get_or_create_from_values(
            protocol="https", host=SHARED_HOST, path="admin",
        ).location
        cls.shared.associate_with_product(cls.product_mine)
        cls.shared.associate_with_product(cls.product_outside)

        # A Location only the caller's product records.
        cls.own = URL.get_or_create_from_values(
            protocol="https", host=OWN_HOST, path="admin",
        ).location
        cls.own.associate_with_product(cls.product_mine)

        # A finding on the other product, referencing the shared row.
        test_type, _ = Test_Type.objects.get_or_create(name="Ref Scoped Scan")
        engagement = Engagement.objects.create(
            product=cls.product_outside, name="ref-scoped-eng",
            target_start=date(2026, 1, 1), target_end=date(2026, 1, 2),
        )
        outside_test = Test.objects.create(
            engagement=engagement, test_type=test_type,
            target_start=datetime(2026, 1, 1, tzinfo=UTC),
            target_end=datetime(2026, 1, 2, tzinfo=UTC),
        )
        cls.outside_finding = Finding.objects.create(
            test=outside_test, title="Ref Scoped Outside Finding", severity="High",
            numerical_severity="S1", description="outside", active=True, verified=False,
            reporter=cls.user,
        )
        cls.shared.associate_with_finding(cls.outside_finding)

    def setUp(self):
        super().setUp()
        self.client.force_login(self.user)

    def _refs(self, location):
        return set(
            LocationProductReference.objects.filter(location=location)
            .values_list("product__name", flat=True),
        )

    def _rename(self, location, host):
        return self.client.post(
            reverse("edit_endpoint", args=(location.id,)),
            {"protocol": "https", "host": host, "path": "admin"},
        )

    def _delete(self, location):
        return self.client.post(
            reverse("delete_endpoint", args=(location.id,)), {"id": location.id},
        )

    def test_rename_leaves_a_location_another_product_records_untouched(self):
        self._rename(self.shared, "renamed-by-attacker.example.test")
        self.shared.refresh_from_db()
        self.shared.url.refresh_from_db()
        self.assertEqual(self.shared.url.host, SHARED_HOST)
        self.assertEqual(self.shared.location_value, f"https://{SHARED_HOST}/admin")

    def test_rename_still_works_when_no_other_product_records_it(self):
        self._rename(self.own, "renamed-by-owner.example.test")
        self.own.url.refresh_from_db()
        self.assertEqual(self.own.url.host, "renamed-by-owner.example.test")

    def test_helper_removes_only_the_given_products_references(self):
        remove_location_references(
            Location.objects.filter(id=self.shared.id),
            Product.objects.filter(id=self.product_mine.id),
        )
        self.assertTrue(Location.objects.filter(id=self.shared.id).exists())
        self.assertEqual(self._refs(self.shared), {self.product_outside.name})
        self.assertTrue(
            LocationFindingReference.objects.filter(
                location_id=self.shared.id, finding=self.outside_finding,
            ).exists(),
        )

    def test_helper_removes_the_row_when_nothing_else_references_it(self):
        remove_location_references(
            Location.objects.filter(id=self.own.id),
            Product.objects.filter(id=self.product_mine.id),
        )
        self.assertFalse(Location.objects.filter(id=self.own.id).exists())

    def test_single_delete_route_stays_denied_without_the_delete_action(self):
        # The object path treats Delete as staff only, so this route was already closed
        # to an ordinary member. The bulk route is the one that was reachable.
        response = self._delete(self.shared)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self._refs(self.shared), {self.product_mine.name, self.product_outside.name})

    def test_bulk_delete_stays_denied_without_the_delete_action(self):
        # Same policy as the single delete route above: membership does not grant delete,
        # so the bulk route removes nothing rather than removing the caller's reference.
        self.client.post(
            reverse("endpoints_bulk_all"),
            {"endpoints_to_update": [self.shared.id], "delete_bulk_endpoints": "1"},
        )
        self.assertTrue(Location.objects.filter(id=self.shared.id).exists())
        self.assertEqual(
            self._refs(self.shared), {self.product_mine.name, self.product_outside.name},
        )

    def test_bulk_delete_stays_denied_for_a_row_only_the_caller_records(self):
        self.client.post(
            reverse("endpoints_bulk_all"),
            {"endpoints_to_update": [self.own.id], "delete_bulk_endpoints": "1"},
        )
        self.assertTrue(Location.objects.filter(id=self.own.id).exists())
