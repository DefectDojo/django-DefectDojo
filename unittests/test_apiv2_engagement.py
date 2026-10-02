"""
API-level regression tests for moving an engagement to a different product via the
REST API (PATCH/PUT /api/v2/engagements/{id}/).

Moving an engagement between products must re-home the endpoints (legacy) or locations
(V3) of that engagement's findings onto the destination product, exactly as the Classic
UI edit_engagement view does. The Pro Vue UI drives this same API path (its engagement
viewsets inherit the OSS EngagementViewSet without overriding update/perform_update), so
wiring the behaviour into the OSS viewset covers Pro too. The move also has to enforce an
edit-permission check on the destination product.
"""
from unittest.mock import patch

from django.urls import reverse
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.location.models import LocationProductReference
from dojo.models import (
    Dojo_User,
    Endpoint,
    Endpoint_Status,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
)
from dojo.url.models import URL

from .dojo_test_case import DojoTestCase, skip_unless_v2, skip_unless_v3

PASSWORD = "testTEST1234!@#$"


class TestMoveEngagementProductAPI(DojoTestCase):

    """
    Moving an engagement to a different product through the REST API must trigger the
    same endpoint/location re-homing as the Classic UI, and must reject a move to a
    destination product the user cannot edit.
    """

    @classmethod
    def setUpTestData(cls):
        cls.product_type = Product_Type.objects.create(name="eng_move_api_pt")
        cls.product_a = Product.objects.create(
            name="eng_move_api_a", description="a", prod_type=cls.product_type,
        )
        cls.product_b = Product.objects.create(
            name="eng_move_api_b", description="b", prod_type=cls.product_type,
        )

        # Superuser drives the happy-path moves (tests 1, 2, 4).
        cls.admin = Dojo_User.objects.create_user(
            username="eng_move_api_admin", password=PASSWORD, is_active=True,
            is_superuser=True, is_staff=True,
        )
        cls.admin_token = Token.objects.create(user=cls.admin)

        # A user authorized on the source product only, used to prove a move to a
        # destination product the user cannot access is rejected (test 3). Legacy OSS
        # authorization keys off product.authorized_users (there is no per-role add/edit
        # split); the same membership grants view+edit on product A but nothing on B.
        cls.limited = Dojo_User.objects.create_user(
            username="eng_move_api_limited", password=PASSWORD, is_active=True,
        )
        cls.product_a.authorized_users.add(cls.limited)
        cls.limited_token = Token.objects.create(user=cls.limited)

    def _engagement_with_finding(self):
        now = timezone.now()
        engagement = Engagement.objects.create(
            name="eng_move_api_eng", product=self.product_a,
            target_start=now, target_end=now,
        )
        test = Test.objects.create(
            engagement=engagement, scan_type="NPM Audit Scan",
            test_type=Test_Type.objects.get(name="NPM Audit Scan"),
            target_start=now, target_end=now,
        )
        finding = Finding.objects.create(test=test, reporter=self.admin)
        return engagement, finding

    def _client(self, token):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        return client

    def _move_url(self, engagement):
        return reverse("engagement-detail", args=[engagement.id])

    # TODO: Delete this after the move to Locations
    @skip_unless_v2
    def test_api_move_engagement_rehomes_endpoints(self):
        engagement, finding = self._engagement_with_finding()
        endpoint = Endpoint.from_uri("host-a.example.com")
        endpoint.product = self.product_a
        endpoint.save()
        endpoint_status = Endpoint_Status.objects.create(finding=finding, endpoint=endpoint)

        client = self._client(self.admin_token)
        response = client.patch(
            self._move_url(engagement), {"product": self.product_b.id}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:1000])

        # The finding's endpoint status now points at an endpoint in the destination product.
        endpoint_status.refresh_from_db()
        self.assertEqual(self.product_b, endpoint_status.endpoint.product)
        # The original source endpoint row is untouched (still in product A).
        endpoint.refresh_from_db()
        self.assertEqual(self.product_a, endpoint.product)

    @skip_unless_v3
    def test_api_move_engagement_rehomes_locations(self):
        engagement, finding = self._engagement_with_finding()
        url = URL(host="host-a.example.com")
        url.save()
        location = url.location
        location.associate_with_finding(finding=finding)
        self.assertTrue(
            LocationProductReference.objects.filter(location=location, product=self.product_a).exists(),
        )

        client = self._client(self.admin_token)
        response = client.patch(
            self._move_url(engagement), {"product": self.product_b.id}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:1000])

        # The location is now associated with the destination product, and the stale
        # source association is dropped since no finding there still references it.
        self.assertTrue(
            LocationProductReference.objects.filter(location=location, product=self.product_b).exists(),
        )
        self.assertFalse(
            LocationProductReference.objects.filter(location=location, product=self.product_a).exists(),
        )

    def test_api_move_engagement_requires_destination_edit_permission(self):
        engagement, _finding = self._engagement_with_finding()

        client = self._client(self.limited_token)
        response = client.patch(
            self._move_url(engagement), {"product": self.product_b.id}, format="json",
        )
        # No edit permission on the destination product -> forbidden.
        self.assertEqual(403, response.status_code, response.content[:1000])
        # The engagement's product is unchanged.
        engagement.refresh_from_db()
        self.assertEqual(self.product_a, engagement.product)

    def test_api_patch_without_product_change_does_no_rehoming(self):
        # A PATCH that does not touch product must not run any endpoint/location
        # re-homing (and must not blow up on the missing "product" in validated_data).
        engagement, _finding = self._engagement_with_finding()

        client = self._client(self.admin_token)
        with patch(
            "dojo.engagement.api.views.reassign_engagement_product_endpoints",
        ) as mock_reassign:
            response = client.patch(
                self._move_url(engagement), {"name": "renamed-no-move"}, format="json",
            )
        self.assertEqual(200, response.status_code, response.content[:1000])
        mock_reassign.assert_not_called()
        engagement.refresh_from_db()
        self.assertEqual(self.product_a, engagement.product)
        self.assertEqual("renamed-no-move", engagement.name)
