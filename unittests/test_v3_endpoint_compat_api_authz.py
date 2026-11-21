"""
Regression tests for object-permission enforcement on the V3 ``/api/v2``
endpoint-compatibility detail routes.

When ``V3_FEATURE_LOCATIONS`` is enabled, ``GET /api/v2/endpoints/<id>/`` and
``GET /api/v2/endpoint_status/<id>/`` are served by the compatibility viewsets
in ``dojo.location.api.endpoint_compat``. Their rows are
``LocationProductReference`` / ``LocationFindingReference`` join rows.

The shared ``UserHasLocationRefPermission`` object-permission class handed the
raw join row straight to the authorization layer, which resolves products,
findings and locations but not these join rows, so the check raised
``NoAuthorizationImplementedError`` -> HTTP 500 for every non-superuser who was
otherwise authorized for the row. (A superuser short-circuits the check and an
unauthorized user is filtered out by the viewset queryset, so both masked the
fault.)

These tests pin the contract: an authorized, non-superuser user can retrieve
the detail routes instead of being handed a 500.
"""

from django.test import override_settings
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.location.models import LocationFindingReference, LocationProductReference
from dojo.location.status import FindingLocationStatus, ProductLocationStatus
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

from .dojo_test_case import DojoTestCase, skip_unless_v3
from .test_rest_framework import BASE_API_URL


@skip_unless_v3
@override_settings(SECURE_SSL_REDIRECT=False)
class V3EndpointCompatApiObjectAuthzTests(DojoTestCase):

    """
    A non-superuser authorized for the product must be able to read the
    compatibility detail routes without hitting the authorization-layer 500.
    """

    def setUp(self):
        super().setUp()
        prod_type = Product_Type.objects.create(name="compat_authz_pt")
        self.product = Product.objects.create(
            name="compat_authz_product",
            description="regression fixture",
            prod_type=prod_type,
        )

        # A plain member of the product: not staff, not superuser. This is the
        # user class the reported 500 flood came from.
        self.user = Dojo_User.objects.create(
            username="compat_authz_member",
            is_active=True,
            is_staff=False,
            is_superuser=False,
        )
        self.product.authorized_users.add(self.user)

        token, _ = Token.objects.get_or_create(user=self.user)
        self.api_client = APIClient()
        self.api_client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

        # A URL location associated with the product -> one LocationProductReference.
        url = URL(protocol="https", host="compat-authz.example.com", path="secret")
        url.clean()
        saved = URL.bulk_get_or_create([url])
        self.location = saved[0].location
        self.product_ref = LocationProductReference.objects.create(
            location=self.location,
            product=self.product,
            status=ProductLocationStatus.Active,
        )

        # A finding in the product, linked to the same location -> one
        # LocationFindingReference, backing the endpoint_status detail route.
        engagement = Engagement.objects.create(
            name="compat_authz_eng",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        test = Test.objects.create(
            engagement=engagement,
            test_type=Test_Type.objects.get_or_create(name="compat_authz_scan")[0],
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.finding = Finding.objects.create(
            test=test,
            title="compat_authz_finding",
            description="x",
            severity="High",
            numerical_severity="S0",
            active=True,
            verified=True,
            reporter=self.user,
        )
        self.finding_ref = LocationFindingReference.objects.create(
            location=self.location,
            finding=self.finding,
            status=FindingLocationStatus.Active,
        )

    def test_authorized_member_can_retrieve_endpoint_detail(self):
        """
        Regression: GET /api/v2/endpoints/<id>/ answered 500 for an authorized
        non-superuser (NoAuthorizationImplementedError on LocationProductReference).
        """
        response = self.api_client.get(
            f"{BASE_API_URL}/endpoints/{self.product_ref.id}/", format="json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["id"], self.product_ref.id)

    def test_authorized_member_can_retrieve_endpoint_status_detail(self):
        """
        The sibling route carries the identical latent fault on
        LocationFindingReference.
        """
        response = self.api_client.get(
            f"{BASE_API_URL}/endpoint_status/{self.finding_ref.id}/", format="json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["id"], self.finding_ref.id)
