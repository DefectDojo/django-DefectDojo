"""
``locations`` as an advertised ``?prefetch=`` option on the Findings and Products API.

Under V3, ``LocationFindingReference.finding`` and ``LocationProductReference.product``
are reverse ForeignKeys named ``locations``. The prefetcher can resolve them (see
``test_apiv2_prefetch_reverse_fk``), but ``get_prefetchable_fields`` -- which feeds the
``prefetch`` parameter enum and the ``prefetch`` response schema in the OpenAPI
document -- only discovered forward ForeignKeys and many-to-many fields, so
``locations`` never appeared in the documented options even though the request worked.

These tests pin the advertised option: it is listed for findings and products while
Locations is enabled and absent while it is disabled, the OpenAPI schema enumerates it
and points at the reference component, and a list/detail request returns the
references keyed by the same ids the finding's ``endpoints`` field carries.
"""

from unittest import skipUnless
from unittest.mock import patch

from django.conf import settings
from django.test import override_settings
from django.utils.timezone import now
from drf_spectacular.settings import spectacular_settings

from dojo.api_v2.prefetch.utils import get_prefetchable_fields
from dojo.api_v2.serializers import FindingSerializer, ProductSerializer
from dojo.location.models import Location, LocationFindingReference, LocationProductReference
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
from unittests.dojo_test_case import DojoAPITestCase, DojoTestCase


def _field_names(serializer_class):
    return [name for name, _ in get_prefetchable_fields(serializer_class)]


@override_settings(V3_FEATURE_LOCATIONS=True, SECURE_SSL_REDIRECT=False)
class PrefetchLocationsOptionTest(DojoAPITestCase):

    """With Locations enabled, ``locations`` is a documented and working prefetch option."""

    @classmethod
    def setUpTestData(cls):
        prod_type, _ = Product_Type.objects.get_or_create(name="PrefetchLocations PT")
        test_type, _ = Test_Type.objects.get_or_create(name="PrefetchLocations Scan")
        cls.admin = Dojo_User.objects.create_superuser(
            username="admin",
            email="admin@prefetch-locations.example",
            password="prefetch-locations-not-a-real-password",  # noqa: S106 -- test-only account
        )

        cls.product = Product.objects.create(
            name="PrefetchLocations Product",
            description="locations prefetch option",
            prod_type=prod_type,
        )
        engagement = Engagement.objects.create(
            name="PrefetchLocations Engagement",
            product=cls.product,
            target_start=now(),
            target_end=now(),
        )
        test = Test.objects.create(
            engagement=engagement,
            test_type=test_type,
            target_start=now(),
            target_end=now(),
            lead=cls.admin,
        )
        cls.finding = Finding.objects.create(
            title="PrefetchLocations Finding",
            test=test,
            reporter=cls.admin,
            severity="Info",
            numerical_severity="S4",
        )

        cls.locations = [
            Location.objects.create(
                location_type="URL",
                location_value=f"https://prefetch-locations-{index}.example.com/",
            )
            for index in range(2)
        ]
        cls.product_references = [
            LocationProductReference.objects.create(
                location=location,
                product=cls.product,
                status=ProductLocationStatus.Active,
            )
            for location in cls.locations
        ]
        cls.finding_references = [
            LocationFindingReference.objects.create(
                location=location,
                finding=cls.finding,
                status=FindingLocationStatus.Active,
            )
            for location in cls.locations
        ]

    def setUp(self):
        self.login_as_admin()

    # ---- advertised options -------------------------------------------------

    def test_locations_is_a_prefetchable_field_on_findings(self):
        self.assertIn(
            ("locations", LocationFindingReference),
            get_prefetchable_fields(FindingSerializer),
        )

    def test_locations_is_a_prefetchable_field_on_products(self):
        self.assertIn(
            ("locations", LocationProductReference),
            get_prefetchable_fields(ProductSerializer),
        )

    def test_forward_relations_are_still_prefetchable(self):
        """Adding the reverse relation must not disturb the existing discovery."""
        names = _field_names(FindingSerializer)
        for name in ("endpoints", "test", "reporter", "notes"):
            self.assertIn(name, names)
        self.assertEqual(1, names.count("locations"), "locations must be advertised exactly once")

    # ---- the request --------------------------------------------------------

    def _assert_finding_references(self, payload, finding_data):
        self.assertIn("locations", payload["prefetch"])
        prefetched = payload["prefetch"]["locations"]

        expected_ids = {reference.pk for reference in self.finding_references}
        # The finding's ``endpoints`` field carries LocationFindingReference ids under V3,
        # and the prefetch payload is keyed by those same ids.
        self.assertEqual(expected_ids, set(finding_data["endpoints"]))
        self.assertEqual({str(pk) for pk in expected_ids}, set(prefetched))

        for reference in self.finding_references:
            entry = prefetched[str(reference.pk)]
            self.assertEqual(reference.pk, entry["id"])
            self.assertEqual(self.finding.pk, entry["finding"])
            self.assertEqual(reference.location.pk, entry["location"])
            self.assertEqual("URL", entry["location_type"])
            self.assertEqual(reference.location.location_value, entry["location_value"])

    def test_list_prefetch_locations_returns_the_finding_references(self):
        response = self.client.get(
            "/api/v2/findings/",
            {"id": self.finding.pk, "prefetch": "locations"},
            format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:1000])
        payload = response.json()
        self.assertEqual(1, payload["count"])
        self._assert_finding_references(payload, payload["results"][0])

    def test_detail_prefetch_locations_returns_the_finding_references(self):
        response = self.client.get(
            f"/api/v2/findings/{self.finding.pk}/",
            {"prefetch": "locations"},
            format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:1000])
        payload = response.json()
        self._assert_finding_references(payload, payload)

    def test_detail_prefetch_locations_returns_the_product_references(self):
        response = self.client.get(
            f"/api/v2/products/{self.product.pk}/",
            {"prefetch": "locations"},
            format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:1000])
        prefetched = response.json()["prefetch"]["locations"]

        expected_ids = {str(reference.pk) for reference in self.product_references}
        self.assertEqual(expected_ids, set(prefetched))
        for reference in self.product_references:
            entry = prefetched[str(reference.pk)]
            self.assertEqual(self.product.pk, entry["product"])
            self.assertEqual(reference.location.pk, entry["location"])
            self.assertEqual(reference.location.location_value, entry["location_value"])

    # ---- the OpenAPI document -----------------------------------------------

    @skipUnless(
        settings.V3_FEATURE_LOCATIONS,
        "the Location routes (and so their schema components) are mounted at import time",
    )
    def test_openapi_schema_advertises_locations(self):
        generator = spectacular_settings.DEFAULT_GENERATOR_CLASS()
        schema = generator.get_schema(request=None, public=True)

        for path, component in (
            ("/api/v2/findings/", "LocationFindingReference"),
            ("/api/v2/products/", "LocationProductReference"),
        ):
            with self.subTest(path=path):
                operation = schema["paths"][path]["get"]
                prefetch_param = next(p for p in operation["parameters"] if p["name"] == "prefetch")
                self.assertIn("locations", prefetch_param["schema"]["items"]["enum"])

                list_ref = operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
                list_component = schema["components"]["schemas"][list_ref.rsplit("/", 1)[-1]]
                locations_property = list_component["properties"]["prefetch"]["properties"]["locations"]
                self.assertEqual(
                    f"#/components/schemas/{component}",
                    locations_property["additionalProperties"]["$ref"],
                )
                self.assertIn(component, schema["components"]["schemas"])


@override_settings(V3_FEATURE_LOCATIONS=False)
class PrefetchLocationsOptionDisabledTest(DojoTestCase):

    """
    With Locations disabled, findings and products carry Endpoints and ``locations`` is not advertised.

    The gate is ``dojo.location.feature.locations_enabled()``; it is patched where the utils
    module looks it up so the test holds whatever resolver a deployment has registered.
    """

    def setUp(self):
        patcher = patch("dojo.api_v2.prefetch.utils.locations_enabled", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_locations_is_not_a_prefetchable_field(self):
        self.assertNotIn("locations", _field_names(FindingSerializer))
        self.assertNotIn("locations", _field_names(ProductSerializer))

    def test_endpoints_remains_a_prefetchable_field_on_findings(self):
        self.assertIn("endpoints", _field_names(FindingSerializer))
