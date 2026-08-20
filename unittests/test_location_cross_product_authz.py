from django.urls import reverse
from django.utils import timezone

from dojo.authorization.roles_permissions import Roles
from dojo.location.models import (
    Location,
    LocationFindingReference,
    LocationProductReference,
    delete_locations_for_products,
)
from dojo.location.status import ProductLocationStatus
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Product,
    Product_Member,
    Product_Type,
    Role,
    Test,
    Test_Type,
    User,
)
from dojo.url.models import URL
from unittests.dojo_test_case import DojoTestCase, skip_unless_v3


@skip_unless_v3
class LocationEndpointViewCrossProductAuthzTest(DojoTestCase):

    """
    The endpoint (Location) UI views resolve objects by location_id.

    A user authorized for one product must not be able to read, edit, or delete a
    Location that belongs only to a different product.
    """

    @classmethod
    def setUpTestData(cls):
        prod_type, _ = Product_Type.objects.get_or_create(name="LOC-XProd PT")
        writer_role = Role.objects.get(id=Roles.Writer)

        cls.product_a = Product.objects.create(name="LOC-XProd Product A", description="A", prod_type=prod_type)
        cls.product_b = Product.objects.create(name="LOC-XProd Product B", description="B", prod_type=prod_type)

        # Alice is authorized only for Product A. Legacy authorization is membership-based
        # via authorized_users, so mirror the Product_Member row onto that M2M.
        cls.alice = User.objects.create_user(
            username="loc_xprod_alice",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
        )
        Product_Member.objects.create(user=cls.alice, product=cls.product_a, role=writer_role)
        cls.product_a.authorized_users.add(Dojo_User.objects.get(pk=cls.alice.pk))

        # A URL location that belongs only to Product B (Alice must not reach it).
        cls.location_b = URL.create_location_from_value("https://private.example.test/secret").location
        LocationProductReference.objects.create(
            location=cls.location_b, product=cls.product_b, status=ProductLocationStatus.Active,
        )
        # A URL location that belongs to Product A (Alice may reach it).
        cls.location_a = URL.create_location_from_value("https://a.example.test/ok").location
        LocationProductReference.objects.create(
            location=cls.location_a, product=cls.product_a, status=ProductLocationStatus.Active,
        )

    def setUp(self):
        super().setUp()
        self.client.force_login(self.alice)

    # A cross-product request is denied by the AuthorizationMiddleware object check
    # (URL_PERMISSIONS maps these views to ("object", Location, ...)). DefectDojo renders
    # PermissionDenied via dojo.views.custom_unauthorized_view, which returns HTTP 400
    # app-wide, so the denied status here is 400. The view-level get_authorized_locations
    # lookup is defense-in-depth behind that middleware check.
    DENIED_STATUS = 400

    def test_view_endpoint_cross_product_is_denied(self):
        response = self.client.get(reverse("view_endpoint", kwargs={"location_id": self.location_b.id}))
        self.assertEqual(self.DENIED_STATUS, response.status_code)

    def test_view_endpoint_own_product_is_allowed(self):
        response = self.client.get(reverse("view_endpoint", kwargs={"location_id": self.location_a.id}))
        self.assertEqual(200, response.status_code)

    def test_edit_endpoint_cross_product_is_denied_and_unchanged(self):
        original_host = self.location_b.url.host
        response = self.client.post(
            reverse("edit_endpoint", kwargs={"location_id": self.location_b.id}),
            {"protocol": "https", "host": "changed.example.test"},
        )
        self.assertEqual(self.DENIED_STATUS, response.status_code)
        self.location_b.url.refresh_from_db()
        self.assertEqual(original_host, self.location_b.url.host)

    def test_delete_endpoint_cross_product_is_denied_and_persists(self):
        response = self.client.post(
            reverse("delete_endpoint", kwargs={"location_id": self.location_b.id}),
            {"id": self.location_b.id},
        )
        self.assertEqual(self.DENIED_STATUS, response.status_code)
        self.assertTrue(Location.objects.filter(pk=self.location_b.id).exists())


@skip_unless_v3
class SharedLocationDeleteScopingTest(DojoTestCase):

    """
    A Location row is deduplicated on its value, so several products share one row.

    Deleting the row takes every product's references with it. Recording a URL another
    product already recorded attaches the caller's product to that existing row, which
    is enough to pass the row-level authorization check. Removing an endpoint must
    therefore drop only the caller's own references and keep a row anything else uses.
    """

    @classmethod
    def setUpTestData(cls):
        prod_type, _ = Product_Type.objects.get_or_create(name="LOC-Del PT")
        writer_role = Role.objects.get(id=Roles.Writer)

        cls.product_a = Product.objects.create(name="LOC-Del Product A", description="A", prod_type=prod_type)
        cls.product_b = Product.objects.create(name="LOC-Del Product B", description="B", prod_type=prod_type)

        cls.alice = User.objects.create_user(
            username="loc_del_alice",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
        )
        Product_Member.objects.create(user=cls.alice, product=cls.product_a, role=writer_role)
        cls.product_a.authorized_users.add(Dojo_User.objects.get(pk=cls.alice.pk))

        engagement = Engagement.objects.create(
            product=cls.product_b, name="LOC-Del eng",
            target_start=timezone.now().date(), target_end=timezone.now().date(),
        )
        test_type, _ = Test_Type.objects.get_or_create(name="LOC-Del scan")
        test = Test.objects.create(
            engagement=engagement, test_type=test_type,
            target_start=timezone.now(), target_end=timezone.now(),
        )
        cls.finding_b = Finding.objects.create(
            test=test, title="LOC-Del Product B finding", severity="High",
            numerical_severity="S1", active=True, verified=False,
            reporter=cls.alice,
        )

    def setUp(self):
        super().setUp()
        self.client.force_login(self.alice)
        # Product B records the URL first, with a finding on it.
        self.shared = URL.create_location_from_value("https://shared.example.test/secret").location
        LocationProductReference.objects.create(
            location=self.shared, product=self.product_b, status=ProductLocationStatus.Active,
        )
        self.shared.associate_with_finding(self.finding_b, audit_time=timezone.now())
        # A row only Product A uses, to prove a legitimate delete still works.
        self.own = URL.create_location_from_value("https://own.example.test/ok").location
        LocationProductReference.objects.create(
            location=self.own, product=self.product_a, status=ProductLocationStatus.Active,
        )

    def _graft(self):
        """Record Product B's URL against Product A, which reuses Product B's row."""
        response = self.client.post(
            reverse("add_endpoint_to_product", kwargs={"product_id": self.product_a.id}),
            {"protocol": "https", "host": "shared.example.test", "path": "secret"},
        )
        self.assertIn(response.status_code, (200, 302))
        self.assertTrue(
            LocationProductReference.objects.filter(location=self.shared, product=self.product_a).exists(),
        )

    def _assert_product_b_intact(self):
        self.assertTrue(Location.objects.filter(pk=self.shared.id).exists())
        self.assertTrue(
            LocationProductReference.objects.filter(location=self.shared, product=self.product_b).exists(),
        )
        self.assertTrue(
            LocationFindingReference.objects.filter(location=self.shared, finding=self.finding_b).exists(),
        )

    def test_bulk_delete_keeps_the_other_products_shared_row(self):
        self._graft()
        response = self.client.post(
            reverse("endpoints_bulk_all"),
            {"endpoints_to_update": [self.shared.id], "delete_bulk_endpoints": "1"},
        )
        self.assertIn(response.status_code, (200, 302))
        self._assert_product_b_intact()
        self.assertFalse(
            LocationProductReference.objects.filter(location=self.shared, product=self.product_a).exists(),
        )

    # The single-endpoint delete view is not reachable with a scoped user under legacy
    # authorization: user_has_permission maps Location_Delete to Action.Delete, which is
    # staff-only, and a staff user is unrestricted so every product is in scope. The two
    # tests below therefore call the helper both views share, with the product scope the
    # views hand it.
    def test_scoped_delete_keeps_the_other_products_shared_row(self):
        self._graft()
        delete_locations_for_products(
            Location.objects.filter(id=self.shared.id),
            Product.objects.filter(id=self.product_a.id),
        )
        self._assert_product_b_intact()
        self.assertFalse(
            LocationProductReference.objects.filter(location=self.shared, product=self.product_a).exists(),
        )

    def test_bulk_delete_still_removes_a_row_only_the_caller_uses(self):
        response = self.client.post(
            reverse("endpoints_bulk_all"),
            {"endpoints_to_update": [self.own.id], "delete_bulk_endpoints": "1"},
        )
        self.assertIn(response.status_code, (200, 302))
        self.assertFalse(Location.objects.filter(pk=self.own.id).exists())

    def test_scoped_delete_still_removes_a_row_only_the_caller_uses(self):
        delete_locations_for_products(
            Location.objects.filter(id=self.own.id),
            Product.objects.filter(id=self.product_a.id),
        )
        self.assertFalse(Location.objects.filter(pk=self.own.id).exists())
