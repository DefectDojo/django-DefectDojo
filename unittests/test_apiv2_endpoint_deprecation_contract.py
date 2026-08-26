"""
The api/v2 contract on a V3-Locations tenant.

Some v2 routes were reported to answer with an hourly 500 flood, because the
deprecated ``Endpoint`` model raises on init and nothing on the v2 surface
caught it. The reported routes were fixed in 3.2.100; these tests hold them
there and check that no other registered route has quietly picked the fault
up.
"""

from django.conf import settings
from django.contrib.auth.models import User
from django.test import override_settings
from django.utils import timezone
from django.utils.module_loading import import_string
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APIRequestFactory

from dojo.api_v2.exception_handler import custom_exception_handler
from dojo.endpoint.models import EndpointDeprecatedError
from dojo.location.models import LocationProductReference
from dojo.location.status import ProductLocationStatus
from dojo.models import (
    IMPORT_CREATED_FINDING,
    Endpoint,
    Endpoint_Status,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Import,
    Test_Import_Finding_Action,
    Test_Type,
    UserContactInfo,
)
from dojo.url.models import URL
from dojo.urls import v2_api

from .dojo_test_case import DojoTestCase, skip_unless_v3
from .test_rest_framework import BASE_API_URL

# Routes that are not plain list routes. Every entry is a route this sweep stops
# protecting, so keep the list short and justified.
SWEEP_EXEMPT = {
    "import-scan",  # POST-only
    "reimport-scan",  # POST-only
    "endpoint_meta_import",  # POST-only, multipart
    "import-languages",  # POST-only
}


@skip_unless_v3
@override_settings(SECURE_SSL_REDIRECT=False)
class ApiV2EndpointDeprecationSweep(DojoTestCase):
    def setUp(self):
        super().setUp()
        self.admin = User.objects.create(
            username="apiv2_sunset_admin",
            is_staff=True,
            is_superuser=True,
        )
        UserContactInfo.objects.create(user=self.admin, block_execution=True)
        token, _ = Token.objects.get_or_create(user=self.admin)
        self.api_client = APIClient()
        self.api_client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

        product_type = Product_Type.objects.create(name="Sunset Org")
        self.product = Product.objects.create(
            name="Sunset Product",
            description="regression fixture",
            prod_type=product_type,
        )
        engagement = Engagement.objects.create(
            name="Sunset Eng",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        test = Test.objects.create(
            engagement=engagement,
            test_type=Test_Type.objects.get_or_create(name="Manual Test")[0],
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.finding = Finding.objects.create(
            test=test,
            title="Sunset finding",
            severity="High",
            description="regression fixture",
            mitigation="n/a",
            impact="n/a",
            reporter=self.admin,
            active=True,
            verified=True,
        )
        test_import = Test_Import.objects.create(test=test, type=Test_Import.IMPORT_TYPE)
        Test_Import_Finding_Action.objects.create(
            test_import=test_import,
            finding=self.finding,
            action=IMPORT_CREATED_FINDING,
        )

        # A migrated tenant still carries legacy Endpoint rows. Without one, every
        # test below passes with nothing to hydrate.
        with Endpoint.allow_endpoint_init():
            endpoint = Endpoint(
                product=self.product,
                protocol="https",
                host="legacy-sunset.example.com",
            )
            endpoint.save()
            Endpoint_Status(endpoint=endpoint, finding=self.finding).save()

        url = URL(protocol="https", host="loc-sunset.example.com")
        url.clean()
        saved = URL.bulk_get_or_create([url])
        LocationProductReference.objects.create(
            location=saved[0].location,
            product=self.product,
            status=ProductLocationStatus.Active,
        )

    def test_endpoints_list_with_a_large_limit(self):
        """The exact failing request: GET /api/v2/endpoints/?limit=500."""
        response = self.api_client.get(f"{BASE_API_URL}/endpoints/?limit=500", format="json")

        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn("results", response.json())

    def test_ordered_test_imports_list(self):
        """The exact failing request: an ordered GET /api/v2/test_imports/."""
        response = self.api_client.get(f"{BASE_API_URL}/test_imports/?o=id", format="json")

        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn("results", response.json())

    def test_no_registered_v2_list_route_answers_5xx(self):
        """
        The audit, as a running check.

        A route that hydrates a legacy Endpoint raises and lands in the exception
        handler's unknown-exception branch, which answers 500. The backstop now
        catches that and answers 410 instead, logged at info, so a route that
        drifts into the deprecation sunset produces no error signal on its own.
        This sweep is what makes both claims checkable: no v2 list route may
        answer 5xx, and none may fall into the deprecation sunset.
        """
        failures = []
        for prefix, _viewset, _basename in v2_api.registry:
            if prefix in SWEEP_EXEMPT:
                continue
            response = self.api_client.get(f"{BASE_API_URL}/{prefix}/", format="json")
            if response.status_code >= 500 or response.status_code == 410:
                failures.append((prefix, response.status_code))

        self.assertEqual(failures, [], f"v2 routes answered 5xx or fell into the deprecation sunset: {failures}")


@skip_unless_v3
@override_settings(SECURE_SSL_REDIRECT=False)
class ApiV2EndpointSunsetBackstop(DojoTestCase):

    """
    Any v2 path that still reaches the deprecated Endpoint model must answer the
    documented sunset contract, not a 500. This is the floor: a path nobody
    converted still answers 410.
    """

    def test_the_configured_handler_answers_410(self):
        """Every other test calls the handler directly. This one goes through DRF's wiring."""
        handler = import_string(settings.REST_FRAMEWORK["EXCEPTION_HANDLER"])
        context = {"request": APIRequestFactory().get("/api/v2/findings/")}

        response = handler(EndpointDeprecatedError("boom"), context)

        self.assertEqual(response.status_code, 410)
        self.assertEqual(response.data["code"], "endpoint_api_sunset")

    def test_endpoint_init_raises_a_dedicated_subclass(self):
        """The backstop matches on a type, so the guard must raise its own class."""
        with self.assertRaises(EndpointDeprecatedError):
            Endpoint(host="sunset.example.com")

        # Existing `except NotImplementedError` handlers must keep working.
        self.assertTrue(issubclass(EndpointDeprecatedError, NotImplementedError))

    def test_the_handler_answers_410_for_the_deprecation_error(self):
        context = {"request": APIRequestFactory().get("/api/v2/findings/")}
        response = custom_exception_handler(EndpointDeprecatedError("boom"), context)

        self.assertEqual(response.status_code, 410)
        self.assertEqual(response.data["code"], "endpoint_api_sunset")
        self.assertEqual(response.data["replacement"], "/api/v2/location/")
        self.assertEqual(
            response.data["docs"],
            "https://docs.defectdojo.com/asset_modelling/locations/pro__migrating_from_endpoints/",
        )
        self.assertIn("Locations", response.data["message"])

    def test_an_unrelated_not_implemented_error_still_answers_500(self):
        """The backstop must be narrow. A genuine bug must stay a 500."""
        context = {"request": APIRequestFactory().get("/api/v2/findings/")}
        response = custom_exception_handler(NotImplementedError("a real bug"), context)

        self.assertEqual(response.status_code, 500)

    def test_the_shipped_403_on_writes_is_unchanged(self):
        """
        The backstop must not move the documented write contract.

        Writes answer 403 today and the migration guide says so. Changing that is
        a separate decision for a minor release.
        """
        admin = User.objects.create(
            username="apiv2_sunset_403_admin",
            is_staff=True,
            is_superuser=True,
        )
        UserContactInfo.objects.create(user=admin, block_execution=True)
        token, _ = Token.objects.get_or_create(user=admin)
        api_client = APIClient()
        api_client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

        response = api_client.post(
            f"{BASE_API_URL}/endpoints/",
            {"host": "write.example.com"},
            format="json",
        )

        self.assertEqual(response.status_code, 403, response.content)
