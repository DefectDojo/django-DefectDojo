"""
Regression tests for cross-tenant authorization on the metadata REST API.

A user with edit on a source product must not be able to re-parent a
metadata record onto a product they have no access to, and this must
hold on every mutating verb (both PUT and PATCH). Also guards that
listing metadata stays available to ordinary (non-superuser) users.
"""
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.authorization.models import Product_Member, Role
from dojo.models import Dojo_User, DojoMeta, Product, Product_Type

from .dojo_test_case import DojoTestCase
from .test_permissions_audit import LegacyAuthMirrorMixin

PASSWORD = "testTEST1234!@#$"


class TestMetadataCrossTenantAuthorization(LegacyAuthMirrorMixin, DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        owner_role = Role.objects.get(name="Owner")

        cls.pt_src = Product_Type.objects.create(name="Meta Authz SRC PT")
        cls.pt_outside = Product_Type.objects.create(name="Meta Authz OUTSIDE PT")
        cls.product_src = Product.objects.create(
            name="Meta Authz Src Product", description="src", prod_type=cls.pt_src,
        )
        cls.product_outside = Product.objects.create(
            name="Meta Authz Outside Product", description="out", prod_type=cls.pt_outside,
        )

        cls.user = Dojo_User.objects.create_user(
            username="meta_authz_user", password=PASSWORD, is_active=True,
        )
        # Edit on the source product only; no membership on product_outside.
        Product_Member.objects.create(
            product=cls.product_src, user=cls.user, role=owner_role,
        )

        cls.meta = DojoMeta.objects.create(
            product=cls.product_src, name="k", value="v",
        )
        cls.token = Token.objects.create(user=cls.user)

    def _client(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Token {self.token.key}")
        return client

    def _relink_payload(self):
        return {"product": self.product_outside.id, "name": "k", "value": "v"}

    def _assert_rejected(self, response):
        self.assertIn(
            response.status_code, [400, 403],
            msg=f"Expected 400/403, got {response.status_code}: {response.content[:500]!r}",
        )

    def test_put_relink_to_unauthorized_product_blocked(self):
        r = self._client().put(
            reverse("metadata-detail", args=(self.meta.id,)),
            self._relink_payload(),
            format="json",
        )
        self._assert_rejected(r)
        self.meta.refresh_from_db()
        self.assertEqual(self.meta.product_id, self.product_src.id)

    def test_patch_relink_to_unauthorized_product_blocked(self):
        r = self._client().patch(
            reverse("metadata-detail", args=(self.meta.id,)),
            self._relink_payload(),
            format="json",
        )
        self._assert_rejected(r)
        self.meta.refresh_from_db()
        self.assertEqual(self.meta.product_id, self.product_src.id)

    def test_metadata_list_available_to_non_superuser(self):
        r = self._client().get(reverse("metadata-list"))
        self.assertEqual(r.status_code, 200, r.content[:500])
