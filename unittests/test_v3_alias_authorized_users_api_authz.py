from django.urls import reverse
from rest_framework import serializers
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.authorization.authorization import user_has_permission
from dojo.authorization.roles_permissions import Permissions
from dojo.authorization.serializer_guards import AuthorizedUsersMemberGuardMixin
from dojo.models import Dojo_User, Product, Product_Type, User
from unittests.dojo_test_case import DojoAPITestCase, versioned_fixtures


def _all_model_serializers():
    found, stack = set(), [serializers.ModelSerializer]
    while stack:
        for sub in stack.pop().__subclasses__():
            if sub not in found:
                found.add(sub)
                stack.append(sub)
    return found


@versioned_fixtures
class V3AliasAuthorizedUsersApiPermissionTest(DojoAPITestCase):

    """
    The asset and organization endpoints are aliases over the same Product and
    Product_Type objects as the product and product_type endpoints, and expose the
    same ``authorized_users`` membership field. Changing that list is a
    member-management operation wherever it is reached, so these pin that the alias
    endpoints require the member-management permission exactly as their
    counterparts do in test_product_authorized_users_api_authz.py.
    """

    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        cls.prod_type = Product_Type.objects.create(name="V3A-Perm PT")
        cls.product = Product.objects.create(
            name="V3A-Perm Product",
            description="product for alias authorized_users permission tests",
            prod_type=cls.prod_type,
        )

        # Alice holds edit on both objects, via authorized_users membership.
        cls.alice = User.objects.create_user(
            username="v3a_alice",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
            is_staff=False,
        )
        cls.product.authorized_users.add(Dojo_User.objects.get(pk=cls.alice.pk))
        cls.prod_type.authorized_users.add(Dojo_User.objects.get(pk=cls.alice.pk))

        # Bob is not a member of either.
        cls.bob = User.objects.create_user(
            username="v3a_bob",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
            is_staff=False,
        )

        # Staff user, who holds the member-management permissions.
        cls.admin = User.objects.create_user(
            username="v3a_admin",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
            is_staff=True,
        )

        cls.asset_url = reverse("asset-detail", args=[cls.product.id])
        cls.organization_url = reverse("organization-detail", args=[cls.prod_type.id])

    def _client_for(self, user):
        token, _ = Token.objects.get_or_create(user=user)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        return client

    def _assert_denied(self, url, obj, edit_permission):
        client = self._client_for(self.alice)
        bob = Dojo_User.objects.get(pk=self.bob.pk)

        self.assertFalse(obj.authorized_users.filter(pk=bob.pk).exists())
        self.assertTrue(
            user_has_permission(Dojo_User.objects.get(pk=self.alice.pk), obj, edit_permission),
        )

        response = client.patch(
            url, {"authorized_users": [self.alice.pk, self.bob.pk]}, format="json",
        )
        self.assertEqual(403, response.status_code, response.content[:400])

        obj.refresh_from_db()
        self.assertFalse(obj.authorized_users.filter(pk=bob.pk).exists())
        self.assertFalse(user_has_permission(bob, obj, edit_permission))

    def test_asset_edit_cannot_add_authorized_users(self):
        self._assert_denied(self.asset_url, self.product, Permissions.Product_Edit)

    def test_organization_edit_cannot_add_authorized_users(self):
        self._assert_denied(self.organization_url, self.prod_type, Permissions.Product_Type_Edit)

    def test_asset_edit_unchanged_authorized_users_is_allowed(self):
        # Replay-safe: resubmitting the current membership set is not a change.
        client = self._client_for(self.alice)
        response = client.patch(
            self.asset_url, {"authorized_users": [self.alice.pk]}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:400])

    def test_asset_ordinary_edit_still_works(self):
        # The endpoint stays usable for an edit-level user; only the membership
        # list is gated.
        client = self._client_for(self.alice)
        response = client.patch(
            self.asset_url, {"description": "edited via alias"}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:400])

    def test_manage_members_permission_can_change_authorized_users(self):
        client = self._client_for(self.admin)
        response = client.patch(
            self.asset_url, {"authorized_users": [self.alice.pk, self.bob.pk]}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:400])

        self.product.refresh_from_db()
        self.assertTrue(self.product.authorized_users.filter(pk=self.bob.pk).exists())

    def test_every_serializer_exposing_authorized_users_carries_the_guard(self):
        """
        Any serializer over Product / Product_Type picks up ``authorized_users``
        unless it excludes it, so each one has to carry the guard. This fails on a
        newly added serializer that forgets it, rather than leaving a gap for a
        report to find.
        """
        reverse("asset-detail", args=[self.product.id])  # force the URLconf, and so every viewset module, to load

        unguarded = []
        for ser in _all_model_serializers():
            meta = getattr(ser, "Meta", None)
            if getattr(meta, "model", None) not in {Product, Product_Type}:
                continue
            declared = getattr(meta, "fields", None)
            excluded = tuple(getattr(meta, "exclude", ()) or ())
            exposed = "authorized_users" not in excluded and (
                declared is None or declared == "__all__" or "authorized_users" in declared
            )
            if exposed and not issubclass(ser, AuthorizedUsersMemberGuardMixin):
                unguarded.append(f"{ser.__module__}.{ser.__name__}")

        self.assertEqual(
            [], sorted(unguarded),
            "these serializers expose authorized_users without the member-management guard; "
            "add AuthorizedUsersMemberGuardMixin, or exclude the field",
        )
