"""
Regression tests for authorization on the writable ``authorized_users`` M2M
exposed by the Product / Product_Type API serializers and their V3 asset /
organization aliases.

Membership management is guarded in the server-rendered views by the
``*_Manage_Members`` permission, but the API serializers exposed
``authorized_users`` as a plain writable field, so a caller with only edit
access to an object could add or remove authorized users through the API.
These tests fix that contract:

* a member with edit access but without the manage-members permission cannot
  change ``authorized_users`` through the API;
* that member can still edit other fields of the object;
* a superuser can still manage ``authorized_users`` through the API.
"""
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase

from dojo.models import Dojo_User, Product, Product_Type, User
from unittests.dojo_test_case import skip_unless_v3, versioned_fixtures


@versioned_fixtures
class AuthorizedUsersApiAuthorizationTest(APITestCase):

    """
    ``member`` has edit access to the product and product type (legacy
    ``authorized_users`` membership) but is not staff, so it lacks the
    manage-members permission. ``outsider`` is the account the member tries to
    smuggle in.
    """

    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        cls.prod_type = Product_Type.objects.create(name="authz_users_pt")
        cls.product = Product.objects.create(
            name="authz_users_product", description="d", prod_type=cls.prod_type,
        )

        cls.member = Dojo_User.objects.create(username="authz_users_member", is_active=True)
        cls.outsider = Dojo_User.objects.create(username="authz_users_outsider", is_active=True)
        # Legacy edit access on both objects, but not staff -> no manage-members.
        cls.product.authorized_users.add(cls.member)
        cls.prod_type.authorized_users.add(cls.member)

        cls.admin = User.objects.get(username="admin")

    def _client(self, user):
        token, _ = Token.objects.get_or_create(user=user)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        return client

    # ------------------------------------------------------------------
    # products
    # ------------------------------------------------------------------
    def test_member_cannot_add_authorized_user_to_product(self):
        client = self._client(self.member)
        response = client.patch(
            reverse("product-detail", args=(self.product.id,)),
            {"authorized_users": [self.member.id, self.outsider.id]},
        )
        self.assertEqual(response.status_code, 403, response.content[:1000])
        self.assertNotIn(self.outsider, self.product.authorized_users.all())

    def test_member_can_still_edit_other_product_fields(self):
        client = self._client(self.member)
        response = client.patch(
            reverse("product-detail", args=(self.product.id,)),
            {"description": "changed by member"},
        )
        self.assertEqual(response.status_code, 200, response.content[:1000])
        self.product.refresh_from_db()
        self.assertEqual(self.product.description, "changed by member")

    def test_superuser_can_change_product_authorized_users(self):
        client = self._client(self.admin)
        response = client.patch(
            reverse("product-detail", args=(self.product.id,)),
            {"authorized_users": [self.member.id, self.outsider.id]},
        )
        self.assertEqual(response.status_code, 200, response.content[:1000])
        self.assertIn(self.outsider, self.product.authorized_users.all())

    # ------------------------------------------------------------------
    # product_types
    # ------------------------------------------------------------------
    def test_member_cannot_add_authorized_user_to_product_type(self):
        client = self._client(self.member)
        response = client.patch(
            reverse("product_type-detail", args=(self.prod_type.id,)),
            {"authorized_users": [self.member.id, self.outsider.id]},
        )
        self.assertEqual(response.status_code, 403, response.content[:1000])
        self.assertNotIn(self.outsider, self.prod_type.authorized_users.all())

    # ------------------------------------------------------------------
    # V3 aliases: assets (Product) and organizations (Product_Type)
    # ------------------------------------------------------------------
    @skip_unless_v3
    def test_member_cannot_add_authorized_user_to_asset(self):
        client = self._client(self.member)
        response = client.patch(
            reverse("asset-detail", args=(self.product.id,)),
            {"authorized_users": [self.member.id, self.outsider.id]},
        )
        self.assertEqual(response.status_code, 403, response.content[:1000])
        self.assertNotIn(self.outsider, self.product.authorized_users.all())

    @skip_unless_v3
    def test_member_cannot_add_authorized_user_to_organization(self):
        client = self._client(self.member)
        response = client.patch(
            reverse("organization-detail", args=(self.prod_type.id,)),
            {"authorized_users": [self.member.id, self.outsider.id]},
        )
        self.assertEqual(response.status_code, 403, response.content[:1000])
        self.assertNotIn(self.outsider, self.prod_type.authorized_users.all())
