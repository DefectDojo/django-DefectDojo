from django.urls import reverse

from dojo.authorization.roles_permissions import Roles
from dojo.location.models import Location, LocationProductReference
from dojo.location.status import ProductLocationStatus
from dojo.models import (
    Dojo_User,
    Product,
    Product_Member,
    Product_Type,
    Role,
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
