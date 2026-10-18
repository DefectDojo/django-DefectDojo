"""
A finding's ``endpoints`` field on an instance with Locations enabled.

On the legacy API a finding's ``endpoints`` listed Endpoint ids, the ids
``/api/v2/endpoints/`` shows, and writing the field replaced the finding's endpoint set
while keeping the status of the endpoints it kept. With Locations enabled the field
listed the finding's LocationFindingReference ids instead, so a client following them to
``/api/v2/endpoints/{id}/`` found the wrong row or none, and a write named rows a legacy
client never sees and reset the status of every endpoint on the finding.
"""

from django.test import override_settings
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.location.models import Location, LocationFindingReference, LocationProductReference
from dojo.location.status import FindingLocationStatus
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
    UserContactInfo,
)
from dojo.url.models import URL

from .dojo_test_case import DojoTestCase, skip_unless_v3
from .test_rest_framework import BASE_API_URL


@skip_unless_v3
@override_settings(SECURE_SSL_REDIRECT=False)
class FindingEndpointsFieldTests(DojoTestCase):

    def setUp(self):
        super().setUp()
        admin = Dojo_User.objects.create(username="finding_endpoints_admin", is_staff=True, is_superuser=True)
        UserContactInfo.objects.create(user=admin, block_execution=True)
        token, _ = Token.objects.get_or_create(user=admin)
        self.api = APIClient()
        self.api.credentials(HTTP_AUTHORIZATION="Token " + token.key)

        prod_type = Product_Type.objects.create(name="finding_endpoints_pt")
        self.product = Product.objects.create(name="finding_endpoints_product", description="x", prod_type=prod_type)
        engagement = Engagement.objects.create(
            name="finding_endpoints_eng",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        test = Test.objects.create(
            engagement=engagement,
            test_type=Test_Type.objects.get_or_create(name="finding_endpoints_scan")[0],
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.finding = Finding.objects.create(
            test=test,
            title="finding_endpoints_finding",
            description="x",
            severity="High",
            numerical_severity="S0",
            active=True,
            verified=True,
            reporter=admin,
        )
        # Two URLs on the finding and one only on the product. Location ids are created
        # before the references, so the reference ids do not line up with them.
        self.kept, self.dropped, self.added = (
            URL.get_or_create_from_values(protocol="https", host=f"{name}.example.com").location
            for name in ("kept", "dropped", "added")
        )
        for location in (self.kept, self.dropped):
            location.associate_with_finding(self.finding)
        self.added.associate_with_product(self.product)
        # Mitigated by hand, so a write that resets statuses shows up.
        LocationFindingReference.objects.filter(location=self.kept, finding=self.finding).update(
            status=FindingLocationStatus.Mitigated,
        )
        # A non-URL location on the finding: not an endpoint, and a write must leave it alone.
        self.other = Location.objects.create(location_type="dependency", location_value="pkg:pypi/example@1.0")
        LocationFindingReference.objects.create(location=self.other, finding=self.finding)

    def _endpoint_id(self, location):
        return LocationProductReference.objects.get(location=location, product=self.product).id

    def _detail(self):
        return f"{BASE_API_URL}/findings/{self.finding.id}/"

    def test_read_lists_the_ids_the_endpoints_route_shows(self):
        body = self.api.get(self._detail(), format="json").json()

        self.assertEqual({self._endpoint_id(self.kept), self._endpoint_id(self.dropped)}, set(body["endpoints"]))
        for endpoint_id in body["endpoints"]:
            endpoint = self.api.get(f"{BASE_API_URL}/endpoints/{endpoint_id}/", format="json")
            self.assertEqual(200, endpoint.status_code, endpoint.content)

    def test_list_reads_the_same_ids(self):
        body = self.api.get(f"{BASE_API_URL}/findings/", {"id": self.finding.id}, format="json").json()

        self.assertEqual({self._endpoint_id(self.kept), self._endpoint_id(self.dropped)}, set(body["results"][0]["endpoints"]))

    def test_write_replaces_the_set_and_keeps_the_status_of_endpoints_it_keeps(self):
        response = self.api.patch(
            self._detail(),
            {"endpoints": [self._endpoint_id(self.kept), self._endpoint_id(self.added)]},
            format="json",
        )

        self.assertEqual(200, response.status_code, response.content)
        self.assertEqual({self._endpoint_id(self.kept), self._endpoint_id(self.added)}, set(response.json()["endpoints"]))
        references = {
            reference.location_id: reference.status
            for reference in LocationFindingReference.objects.filter(finding=self.finding)
        }
        self.assertEqual(FindingLocationStatus.Mitigated, references[self.kept.id])
        self.assertIn(self.added.id, references)
        self.assertNotIn(self.dropped.id, references)
        self.assertIn(self.other.id, references)

    def test_write_without_the_field_changes_nothing(self):
        response = self.api.patch(self._detail(), {"title": "renamed"}, format="json")

        self.assertEqual(200, response.status_code, response.content)
        self.assertEqual(
            {self.kept.id, self.dropped.id, self.other.id},
            set(LocationFindingReference.objects.filter(finding=self.finding).values_list("location_id", flat=True)),
        )
