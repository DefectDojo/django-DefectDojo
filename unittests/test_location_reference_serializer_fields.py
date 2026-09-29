"""
Regression tests for the ``location_type`` / ``location_value`` fields on the Location
reference API endpoints (``/api/v2/location_products/`` and ``/api/v2/location_findings/``).

Both serializers declared the two fields as ``CharField(read_only=True)`` with no
``source``, but they live on the related ``Location``, not on the reference (through)
model. DRF treats the resulting ``AttributeError`` on a non-required read-only field as
``SkipField``, so every response silently omitted both fields: a row carried only the
``location`` id, and a client had to make a second request to learn which host or URL it
referred to.
"""
from django.urls import reverse
from django.utils.timezone import now
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase

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
from unittests.dojo_test_case import skip_unless_v3, versioned_fixtures


# Regression: location reference endpoints omitted location_type/location_value from every response
@skip_unless_v3
@versioned_fixtures
class LocationReferenceSerializerFieldsTest(APITestCase):

    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        cls.admin = Dojo_User.objects.create(username="locref_fields_admin", is_active=True, is_superuser=True)
        prod_type = Product_Type.objects.create(name="locref_fields_pt")
        cls.product = Product.objects.create(name="locref_fields_product", description="p", prod_type=prod_type)
        cls.other_product = Product.objects.create(name="locref_fields_other", description="o", prod_type=prod_type)
        test_type, _ = Test_Type.objects.get_or_create(name="locref_fields_scan")
        engagement = Engagement.objects.create(
            name="locref_fields_eng", product=cls.product, target_start=now(), target_end=now(),
        )
        test = Test.objects.create(engagement=engagement, test_type=test_type, target_start=now(), target_end=now())
        cls.finding = Finding.objects.create(
            test=test, title="locref_fields_finding", description="f",
            severity="High", numerical_severity="S0", active=True, verified=True,
        )

        cls.location = Location.objects.create(location_type="URL", location_value="https://server01.example.com/")
        cls.product_ref = LocationProductReference.objects.create(
            location=cls.location, product=cls.product, status=ProductLocationStatus.Active,
        )
        cls.finding_ref = LocationFindingReference.objects.create(
            location=cls.location, finding=cls.finding, status=FindingLocationStatus.Active,
        )

    def setUp(self):
        token, _ = Token.objects.get_or_create(user=self.admin)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

    def assert_location_fields(self, row, where):
        persisted = Location.objects.get(pk=row["location"])
        for field in ("location_type", "location_value"):
            with self.subTest(where=where, field=field):
                self.assertIn(field, row, msg=f"{where}: {field} missing, row keys={sorted(row)}")
                self.assertEqual(
                    row[field], getattr(persisted, field),
                    msg=f"{where}: expected {field}={getattr(persisted, field)!r}, got {row[field]!r}",
                )

    def test_location_products_list_and_detail(self):
        response = self.client.get(reverse("location_products-list"), {"product": self.product.id})
        self.assertEqual(response.status_code, 200, response.content[:1000])
        rows = [r for r in response.json()["results"] if r["id"] == self.product_ref.id]
        self.assertEqual(len(rows), 1, response.content[:1000])
        self.assert_location_fields(rows[0], "location_products list")

        response = self.client.get(reverse("location_products-detail", args=[self.product_ref.id]))
        self.assertEqual(response.status_code, 200, response.content[:1000])
        self.assert_location_fields(response.json(), "location_products detail")

    def test_location_products_create_response(self):
        response = self.client.post(
            reverse("location_products-list"),
            {"product": self.other_product.id, "location": self.location.id, "status": ProductLocationStatus.Active},
        )
        self.assertEqual(response.status_code, 201, response.content[:1000])
        self.assert_location_fields(response.json(), "location_products create")

    def test_location_findings_list_and_detail(self):
        response = self.client.get(reverse("location_findings-list"), {"finding": self.finding.id})
        self.assertEqual(response.status_code, 200, response.content[:1000])
        rows = [r for r in response.json()["results"] if r["id"] == self.finding_ref.id]
        self.assertEqual(len(rows), 1, response.content[:1000])
        self.assert_location_fields(rows[0], "location_findings list")

        response = self.client.get(reverse("location_findings-detail", args=[self.finding_ref.id]))
        self.assertEqual(response.status_code, 200, response.content[:1000])
        self.assert_location_fields(response.json(), "location_findings detail")
