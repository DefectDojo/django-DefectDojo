"""
``/api/v2/endpoint_status/`` names the endpoint by the id ``/api/v2/endpoints/`` lists.

Regression: with Locations on, ``/api/v2/endpoints/`` serves product references of URL Locations,
and its ``id`` is the reference's own id. ``/api/v2/endpoint_status/`` returned the Location's id
in its ``endpoint`` field instead, while its ``?endpoint=`` filter read a reference id. The two ids
often coincide, so it mostly looked right, but where they differ an id copied from
``endpoint_status`` named the wrong endpoint or none. The field also ran one query per row.
"""

from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.location.models import LocationFindingReference, LocationProductReference
from dojo.location.status import FindingLocationStatus, ProductLocationStatus
from dojo.models import Dojo_User, Engagement, Finding, Product, Product_Type, Test, Test_Type
from dojo.url.models import URL

from .dojo_test_case import DojoTestCase, skip_unless_v3
from .test_rest_framework import BASE_API_URL


def _url_location(host):
    url = URL(protocol="https", host=host, path="login")
    url.clean()
    return URL.bulk_get_or_create([url])[0].location


@skip_unless_v3
@override_settings(SECURE_SSL_REDIRECT=False)
class V3EndpointStatusReferenceIdTests(DojoTestCase):

    def setUp(self):
        super().setUp()
        prod_type = Product_Type.objects.create(name="status_ref_pt")
        self.first = Product.objects.create(name="status_ref_first", description="x", prod_type=prod_type)
        self.second = Product.objects.create(name="status_ref_second", description="x", prod_type=prod_type)
        self.test_type = Test_Type.objects.get_or_create(name="status_ref_scan")[0]
        self.user = Dojo_User.objects.create(username="status_ref_admin", is_active=True, is_staff=True, is_superuser=True)
        token, _ = Token.objects.get_or_create(user=self.user)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

        # Reference rows for other Locations first, so a reference id and its Location id differ.
        for n in range(3):
            LocationProductReference.objects.create(location=_url_location(f"status-ref-pad-{n}.example.com"), product=self.first, status=ProductLocationStatus.Active)

        # One Location shared by both products: two references, two findings.
        self.location = _url_location("status-ref-shared.example.com")
        self.first_ref = LocationProductReference.objects.create(location=self.location, product=self.first, status=ProductLocationStatus.Active)
        self.second_ref = LocationProductReference.objects.create(location=self.location, product=self.second, status=ProductLocationStatus.Active)
        self.first_status = self._status(self.first, "status_ref_first_finding")
        self.second_status = self._status(self.second, "status_ref_second_finding")
        self.assertNotEqual(self.second_ref.id, self.location.id, "the fixture must make the ids differ")

    def _status(self, product, title, location=None):
        engagement = Engagement.objects.create(name=f"{title} eng", product=product, target_start=timezone.now(), target_end=timezone.now())
        test = Test.objects.create(engagement=engagement, test_type=self.test_type, target_start=timezone.now(), target_end=timezone.now())
        finding = Finding.objects.create(test=test, title=title, description="x", severity="High", numerical_severity="S1", active=True, verified=True, reporter=self.user)
        return LocationFindingReference.objects.create(location=location or self.location, finding=finding, status=FindingLocationStatus.Active)

    def _get(self, path, **params):
        response = self.client.get(f"{BASE_API_URL}/{path}/", params, format="json")
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()

    def test_endpoint_is_the_id_the_endpoint_list_shows_for_the_findings_product(self):
        listed = {(row["location_id"], row["product"]): row["id"] for row in self._get("endpoints", limit=100)["results"]}
        statuses = {row["id"]: row for row in self._get("endpoint_status", limit=100)["results"]}

        for status, product in ((self.first_status, self.first), (self.second_status, self.second)):
            row = statuses[status.id]
            self.assertEqual(row["endpoint"], listed[self.location.id, product.id], f"endpoint={row['endpoint']} location_id={row['location_id']}")
            self.assertEqual(row["location_id"], self.location.id)
        self.assertEqual(self._get(f"endpoint_status/{self.second_status.id}")["endpoint"], self.second_ref.id)

    def test_filtering_by_that_id_returns_that_products_status_only(self):
        # A legacy Endpoint_Status always belonged to its endpoint's product, so the other product's
        # finding on the same shared Location is not this endpoint's status.
        found = [row["id"] for row in self._get("endpoint_status", endpoint=self.second_ref.id)["results"]]
        self.assertEqual(found, [self.second_status.id])
        found = [row["id"] for row in self._get("endpoint_status", endpoint=self.first_ref.id)["results"]]
        self.assertEqual(found, [self.first_status.id])

    def test_an_unknown_endpoint_id_matches_nothing(self):
        self.assertEqual(self._get("endpoint_status", endpoint=999999)["results"], [])

    def test_a_finding_without_a_product_reference_names_no_endpoint(self):
        orphan = self._status(self.first, "status_ref_orphan", location=_url_location("status-ref-orphan.example.com"))
        self.assertIsNone(self._get(f"endpoint_status/{orphan.id}")["endpoint"])

    def test_the_list_costs_the_same_queries_for_more_rows(self):
        def count():
            with CaptureQueriesContext(connection) as queries:
                self._get("endpoint_status", limit=100)
            return len(queries)

        before = count()
        for n in range(4):
            self._status(self.second, f"status_ref_more_{n}")
        self.assertEqual(count(), before, "the endpoint field must not query per row")
