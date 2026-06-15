"""
Regression tests for object-permission enforcement on the V3 endpoint
(``dojo.url.ui``) routes.

The V3 routes carry a ``location_id`` kwarg and operate on
``dojo.location.models.Location`` rows. They share URL names with the
legacy endpoint UI, so the existing ``URL_PERMISSIONS`` mapping and the
``AuthorizationMiddleware`` need to line up with the active route's
model and kwarg for the per-object check to actually run.

These tests fix the contract: an authenticated user who has no
membership on the product backing a Location must not be able to view,
edit, delete, attach metadata to, or reach Location-scoped routes for
that Location.
"""
from unittest.mock import MagicMock

from django.core.exceptions import PermissionDenied
from django.test import RequestFactory
from django.urls import reverse
from django.utils.timezone import now

from dojo.authorization.middleware import AuthorizationMiddleware
from dojo.authorization.url_permissions import URL_PERMISSIONS
from dojo.location.models import Location
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
)
from dojo.url.models import URL
from unittests.dojo_test_case import DojoTestCase, skip_unless_v3


@skip_unless_v3
class V3EndpointRouteAuthorizationTests(DojoTestCase):

    """
    Two products, two users -- each user is authorized only for their own
    product. Locations are created and associated to one product apiece.
    Each test crosses the membership boundary and asserts the request is
    rejected.
    """

    @classmethod
    def setUpTestData(cls):
        cls.prod_type = Product_Type.objects.create(name="v3_authz_pt")
        cls.product_a = Product.objects.create(
            name="v3_authz_product_a",
            description="a",
            prod_type=cls.prod_type,
        )
        cls.product_b = Product.objects.create(
            name="v3_authz_product_b",
            description="b",
            prod_type=cls.prod_type,
        )

        cls.user_a = Dojo_User.objects.create(username="v3_authz_user_a", is_active=True)
        cls.user_b = Dojo_User.objects.create(username="v3_authz_user_b", is_active=True)
        # Legacy authorization uses ``authorized_users`` directly.
        cls.product_a.authorized_users.add(cls.user_a)
        cls.product_b.authorized_users.add(cls.user_b)

        # Each Location is tied to exactly one product.
        cls.url_a = URL.get_or_create_from_object(
            URL.from_value("https://product-a.example.test/secret"),
        )
        cls.url_a.location.associate_with_product(cls.product_a)
        cls.location_a = cls.url_a.location

        cls.url_b = URL.get_or_create_from_object(
            URL.from_value("https://product-b.example.test/secret"),
        )
        cls.url_b.location.associate_with_product(cls.product_b)
        cls.location_b = cls.url_b.location

        # A Finding whose product is product_b -- used for add_endpoint_to_finding.
        test_type, _ = Test_Type.objects.get_or_create(name="v3_authz_scan")
        engagement = Engagement.objects.create(
            name="v3_authz_eng",
            product=cls.product_b,
            target_start=now(),
            target_end=now(),
        )
        test = Test.objects.create(
            engagement=engagement,
            test_type=test_type,
            target_start=now(),
            target_end=now(),
        )
        cls.finding_in_b = Finding.objects.create(
            test=test,
            title="v3_authz_finding",
            description="x",
            severity="High",
            numerical_severity="S0",
            active=True,
            verified=True,
            reporter=cls.user_b,
        )

    # ------------------------------------------------------------------
    # Positive control: the authorized user can reach their own Location.
    # ------------------------------------------------------------------
    def test_authorized_user_can_view_own_location(self):
        self.client.force_login(self.user_a)
        response = self.client.get(reverse("view_endpoint", args=(self.location_a.id,)))
        self.assertEqual(response.status_code, 200)

    # ------------------------------------------------------------------
    # View / view-host / report routes must reject cross-product access.
    # ------------------------------------------------------------------
    def test_view_endpoint_rejects_cross_product(self):
        self.client.force_login(self.user_a)
        response = self.client.get(reverse("view_endpoint", args=(self.location_b.id,)))
        self.assertEqual(response.status_code, 400)

    def test_view_endpoint_host_rejects_cross_product(self):
        self.client.force_login(self.user_a)
        response = self.client.get(reverse("view_endpoint_host", args=(self.location_b.id,)))
        self.assertEqual(response.status_code, 400)

    def test_endpoint_report_rejects_cross_product(self):
        self.client.force_login(self.user_a)
        response = self.client.get(reverse("endpoint_report", args=(self.location_b.id,)))
        self.assertEqual(response.status_code, 400)

    def test_endpoint_host_report_rejects_cross_product(self):
        self.client.force_login(self.user_a)
        response = self.client.get(reverse("endpoint_host_report", args=(self.location_b.id,)))
        self.assertEqual(response.status_code, 400)

    # ------------------------------------------------------------------
    # Edit / delete routes must reject cross-product mutation.
    # ------------------------------------------------------------------
    def test_edit_endpoint_rejects_cross_product(self):
        self.client.force_login(self.user_a)
        original_host = self.url_b.host
        response = self.client.post(
            reverse("edit_endpoint", args=(self.location_b.id,)),
            data={
                "protocol": "https",
                "host": "changed.example.test",
                "path": "changed",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.url_b.refresh_from_db()
        self.assertEqual(self.url_b.host, original_host)

    def test_delete_endpoint_rejects_cross_product(self):
        self.client.force_login(self.user_a)
        response = self.client.post(
            reverse("delete_endpoint", args=(self.location_b.id,)),
            data={"id": self.location_b.id},
        )
        self.assertEqual(response.status_code, 400)
        self.assertTrue(Location.objects.filter(pk=self.location_b.id).exists())

    # ------------------------------------------------------------------
    # Metadata routes go through the same view + URL name overlap.
    # ------------------------------------------------------------------
    def test_add_endpoint_meta_data_rejects_cross_product(self):
        self.client.force_login(self.user_a)
        response = self.client.get(reverse("add_endpoint_meta_data", args=(self.location_b.id,)))
        self.assertEqual(response.status_code, 400)

    def test_edit_endpoint_meta_data_rejects_cross_product(self):
        self.client.force_login(self.user_a)
        response = self.client.get(reverse("edit_endpoint_meta_data", args=(self.location_b.id,)))
        self.assertEqual(response.status_code, 400)

    # ------------------------------------------------------------------
    # The /endpoints/finding/<id>/add route ties URL creation to a Finding,
    # so authorization has to be checked against the Finding's product --
    # not against an unrelated Product whose pk coincides with finding_id.
    # ------------------------------------------------------------------
    def test_add_endpoint_to_finding_rejects_cross_product(self):
        self.client.force_login(self.user_a)
        response = self.client.post(
            reverse("add_endpoint_to_finding", args=(self.finding_in_b.id,)),
            data={
                "protocol": "https",
                "host": "attacker.example.test",
                "path": "",
            },
        )
        self.assertEqual(response.status_code, 400)


class AuthorizationMiddlewareKwargContractTests(DojoTestCase):

    """
    The middleware must not silently skip an object-permission check when
    the configured kwarg is absent from ``view_kwargs``. A missing kwarg
    is a sign that the URL pattern and the URL_PERMISSIONS entry have
    drifted apart; treating that as "allowed" is unsafe.
    """

    def test_missing_configured_kwarg_is_treated_as_denied(self):
        middleware = AuthorizationMiddleware(get_response=lambda _request: None)
        request = RequestFactory().get("/somepath")
        request.user = Dojo_User.objects.create(username="middleware_kwarg_test_user", is_active=True)

        resolver_match = MagicMock()
        # Pick any URL name that has an object check configured.
        resolver_match.url_name = next(
            name for name, checks in URL_PERMISSIONS.items()
            if checks and checks[0][0] == "object"
        )
        request.resolver_match = resolver_match

        def _view(_request, **_kwargs):
            return None

        with self.assertRaises(PermissionDenied):
            middleware.process_view(request, view_func=_view, view_args=(), view_kwargs={})
