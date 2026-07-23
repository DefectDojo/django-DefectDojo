from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.models import Dojo_User, Product, Product_Type, User
from unittests.dojo_test_case import DojoAPITestCase, versioned_fixtures


@versioned_fixtures
class ProductAuthorizedUsersApiPermissionTest(DojoAPITestCase):

    """
    Permission coverage for the ``authorized_users`` field on the Product API.

    ``authorized_users`` is exposed as a writable field on ProductSerializer.
    Changing it is a member-management operation, gated behind
    ``Product_Manage_Members`` -- the same permission the web UI requires in
    dojo.product.ui.views.add_product_authorized_users. The rest of the
    endpoint is governed by ``Product_Edit``. These tests pin that changes to
    the membership list go through the member-management permission, while
    ordinary product edits and no-op submissions are unaffected.
    """

    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        prod_type = Product_Type.objects.create(name="PAU-Perm PT")
        cls.product = Product.objects.create(
            name="PAU-Perm Product",
            description="product for authorized_users permission tests",
            prod_type=prod_type,
        )

        # Alice: holds Product_Edit on the product (via authorized_users membership).
        cls.alice = User.objects.create_user(
            username="pau_alice",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
            is_staff=False,
        )
        cls.product.authorized_users.add(Dojo_User.objects.get(pk=cls.alice.pk))

        # Bob: another user, not initially a member of the product.
        cls.bob = User.objects.create_user(
            username="pau_bob",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
            is_staff=False,
        )

        # Staff user, who holds Product_Manage_Members.
        cls.admin = User.objects.create_user(
            username="pau_admin",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
            is_staff=True,
        )

        cls.detail_url = reverse("product-detail", args=[cls.product.id])

    def _client_for(self, user):
        token, _ = Token.objects.get_or_create(user=user)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        return client

    def test_product_edit_cannot_add_authorized_users(self):
        client = self._client_for(self.alice)

        # Product_Edit alone permits ordinary field updates.
        response = client.patch(
            self.detail_url, {"description": "edited via product edit"}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:500])

        # Adding a user to authorized_users requires Product_Manage_Members.
        self.assertFalse(self.product.authorized_users.filter(pk=self.bob.pk).exists())
        response = client.patch(
            self.detail_url,
            {"authorized_users": [self.alice.pk, self.bob.pk]},
            format="json",
        )
        self.assertEqual(403, response.status_code, response.content[:500])

        self.product.refresh_from_db()
        self.assertFalse(self.product.authorized_users.filter(pk=self.bob.pk).exists())
        self.assertTrue(self.product.authorized_users.filter(pk=self.alice.pk).exists())

    def test_product_edit_cannot_replace_authorized_users(self):
        # PATCH replaces the M2M via .set(); replacing the list is also a
        # member-management change and requires Product_Manage_Members.
        client = self._client_for(self.alice)
        response = client.patch(
            self.detail_url, {"authorized_users": [self.bob.pk]}, format="json",
        )
        self.assertEqual(403, response.status_code, response.content[:500])

        self.product.refresh_from_db()
        self.assertTrue(self.product.authorized_users.filter(pk=self.alice.pk).exists())
        self.assertFalse(self.product.authorized_users.filter(pk=self.bob.pk).exists())

    def test_product_edit_unchanged_authorized_users_is_allowed(self):
        # Replay-safe: re-submitting the current membership set unchanged is not
        # a member-management change and is accepted.
        client = self._client_for(self.alice)
        response = client.patch(
            self.detail_url, {"authorized_users": [self.alice.pk]}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:500])

    def test_non_member_cannot_change_authorized_users(self):
        # A user who is not a member of the product cannot retrieve it (the
        # viewset queryset is scoped to authorized products), so the PATCH is
        # rejected before the member-management check is reached.
        client = self._client_for(self.bob)

        response = client.get(self.detail_url)
        self.assertIn(response.status_code, {403, 404}, response.content[:500])

        response = client.patch(
            self.detail_url, {"authorized_users": [self.bob.pk]}, format="json",
        )
        self.assertIn(response.status_code, {403, 404}, response.content[:500])

        self.product.refresh_from_db()
        self.assertFalse(self.product.authorized_users.filter(pk=self.bob.pk).exists())

    def test_manage_members_permission_can_change_authorized_users(self):
        # Product_Manage_Members (staff) can update the membership list.
        client = self._client_for(self.admin)
        response = client.patch(
            self.detail_url,
            {"authorized_users": [self.alice.pk, self.bob.pk]},
            format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:500])

        self.product.refresh_from_db()
        self.assertTrue(self.product.authorized_users.filter(pk=self.bob.pk).exists())
