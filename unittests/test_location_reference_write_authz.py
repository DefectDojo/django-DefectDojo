"""
Regression tests for write authorization on the Location reference API
endpoints (``/api/v2/location_products/`` and ``/api/v2/location_findings/``).

Both serializers expose the reference fields with ``fields = "__all__"``, so
the ``location`` foreign key is writable. The permission classes authorized
only the ``product`` / ``finding`` foreign key, so a user could attach a
location they are not allowed to see to a product/finding they own and then
read it back (the reference serializers expose ``location_value``). Because a
Location is authorized through the products it is associated with, the write
path must also authorize the ``location`` foreign key.
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


@skip_unless_v3
@versioned_fixtures
class LocationReferenceWriteAuthorizationTest(APITestCase):

    """
    Two products for the attacker and one for the victim. The victim location
    is associated only with the victim product, so the attacker has no
    legitimate access to it.
    """

    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        cls.prod_type = Product_Type.objects.create(name="locref_write_pt")
        cls.product_a = Product.objects.create(name="locref_write_a", description="a", prod_type=cls.prod_type)
        cls.product_a2 = Product.objects.create(name="locref_write_a2", description="a2", prod_type=cls.prod_type)
        cls.product_b = Product.objects.create(name="locref_write_b", description="b", prod_type=cls.prod_type)

        # Attacker is a member of product_a / product_a2 only.
        cls.user_a = Dojo_User.objects.create(username="locref_write_user_a", is_active=True)
        cls.product_a.authorized_users.add(cls.user_a)
        cls.product_a2.authorized_users.add(cls.user_a)
        # Victim owns product_b.
        cls.user_b = Dojo_User.objects.create(username="locref_write_user_b", is_active=True)
        cls.product_b.authorized_users.add(cls.user_b)

        # Victim location: associated only with product_b -- the attacker
        # cannot legitimately see it.
        cls.victim_location = Location.objects.create(
            location_type="URL", location_value="https://victim.example/secret",
        )
        LocationProductReference.objects.create(
            location=cls.victim_location, product=cls.product_b, status=ProductLocationStatus.Active,
        )

        # A location the attacker can legitimately see (via product_a).
        cls.own_location = Location.objects.create(
            location_type="URL", location_value="https://own.example/ok",
        )
        LocationProductReference.objects.create(
            location=cls.own_location, product=cls.product_a, status=ProductLocationStatus.Active,
        )

        # A finding in product_a for the finding-reference cases.
        test_type, _ = Test_Type.objects.get_or_create(name="locref_write_scan")
        engagement = Engagement.objects.create(
            name="locref_write_eng", product=cls.product_a, target_start=now(), target_end=now(),
        )
        test = Test.objects.create(
            engagement=engagement, test_type=test_type, target_start=now(), target_end=now(),
        )
        cls.finding_a = Finding.objects.create(
            test=test, title="locref_write_finding", description="x",
            severity="High", numerical_severity="S0", active=True, verified=True,
        )

    def _client(self, user):
        token = Token.objects.create(user=user)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        return client

    # ------------------------------------------------------------------
    # location_products
    # ------------------------------------------------------------------
    def test_cannot_bind_unauthorized_location_to_product(self):
        client = self._client(self.user_a)
        response = client.post(
            reverse("location_products-list"),
            {"product": self.product_a.id, "location": self.victim_location.id, "status": ProductLocationStatus.Active},
        )
        self.assertEqual(response.status_code, 403, response.content[:1000])
        self.assertFalse(
            LocationProductReference.objects.filter(product=self.product_a, location=self.victim_location).exists(),
        )

    def test_can_bind_authorized_location_to_product(self):
        client = self._client(self.user_a)
        response = client.post(
            reverse("location_products-list"),
            {"product": self.product_a2.id, "location": self.own_location.id, "status": ProductLocationStatus.Active},
        )
        self.assertEqual(response.status_code, 201, response.content[:1000])

    # ------------------------------------------------------------------
    # location_findings
    # ------------------------------------------------------------------
    def test_cannot_bind_unauthorized_location_to_finding(self):
        client = self._client(self.user_a)
        response = client.post(
            reverse("location_findings-list"),
            {"finding": self.finding_a.id, "location": self.victim_location.id, "status": FindingLocationStatus.Active},
        )
        self.assertEqual(response.status_code, 403, response.content[:1000])
        self.assertFalse(
            LocationFindingReference.objects.filter(finding=self.finding_a, location=self.victim_location).exists(),
        )
