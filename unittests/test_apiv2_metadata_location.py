"""
Regression: ``MetaSerializer`` under Locations.

The Pro location page adds metadata through the flat ``metadata`` endpoint, sending
``location`` (and the asset scope, ``location_product``). Two things broke that:

- ``endpoint`` is a ``PrimaryKeyRelatedField`` with ``default=None``, so the key is always
  present in validated data, and the endpoint→location compatibility line replaced the
  real ``location`` with ``None`` ("Metadata entries need either a product, endpoint,
  location or a finding" for a payload that named a location).
- ``location_product`` is ``editable=False`` on the model, so ``ModelSerializer`` dropped
  it and every entry written through the API landed unscoped.
"""

from unittest.mock import patch

from django.urls import reverse
from rest_framework.test import APIRequestFactory

from dojo.api_v2.serializers import MetaSerializer
from dojo.authorization.api_permissions import UserHasDojoMetaPermission
from dojo.authorization.roles_permissions import Roles
from dojo.location.models import LocationProductReference
from dojo.location.status import ProductLocationStatus
from dojo.models import Dojo_User, DojoMeta, Product, Product_Member, Product_Type, Role, User
from dojo.url.models import URL

from .dojo_test_case import DojoAPITestCase, DojoTestCase, skip_unless_v3


@patch("dojo.api_v2.serializers.locations_enabled", new=lambda: True)
class TestMetaSerializerLocation(DojoTestCase):
    @classmethod
    def setUpTestData(cls):
        cls.product_type = Product_Type.objects.create(name="Meta Loc PT")
        cls.product = Product.objects.create(name="Meta Loc Product", description="p", prod_type=cls.product_type)
        cls.location = URL.get_or_create_from_values(
            protocol="https", host="meta-location.example.test", path="",
        ).location
        LocationProductReference.objects.create(location=cls.location, product=cls.product)
        cls.other_product = Product.objects.create(name="Meta Loc Other Product", description="o", prod_type=cls.product_type)
        cls.member = Dojo_User.objects.create(username="meta_loc_member", is_active=True)
        cls.product.authorized_users.add(cls.member)
        cls.superuser = Dojo_User.objects.create(username="meta_loc_superuser", is_active=True, is_superuser=True)

    def _context(self, user):
        request = APIRequestFactory().post("/api/v2/metadata/")
        request.user = user
        return {"request": request}

    def test_location_only_payload_takes_the_callers_product(self):
        # The member's products reference the location through one product, so that is the scope.
        serializer = MetaSerializer(
            data={"location": self.location.id, "name": "environment", "value": "prod"}, context=self._context(self.member),
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.validated_data["location"], self.location)
        self.assertEqual(serializer.validated_data["location_product"], self.product)

    def test_location_only_payload_needs_a_scope_when_it_is_ambiguous(self):
        LocationProductReference.objects.create(location=self.location, product=self.other_product)
        self.other_product.authorized_users.add(self.member)
        for user in (self.member, self.superuser):
            with self.subTest(user=user.username):
                serializer = MetaSerializer(
                    data={"location": self.location.id, "name": "environment", "value": "prod"}, context=self._context(user),
                )
                self.assertFalse(serializer.is_valid())
                self.assertIn("location_product", serializer.errors)

    def test_endpoint_key_still_maps_to_location(self):
        # Legacy clients name the location through ``endpoint``; that compatibility stays.
        serializer = MetaSerializer(
            data={"endpoint": self.location.id, "name": "environment", "value": "prod"}, context=self._context(self.member),
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.validated_data["location"], self.location)
        self.assertEqual(serializer.validated_data["location_product"], self.product)

    def test_location_product_scope_is_persisted(self):
        serializer = MetaSerializer(
            data={"location": self.location.id, "location_product": self.product.id, "name": "owner", "value": "ops"},
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        row = serializer.save()
        persisted = DojoMeta.objects.get(id=row.id)
        self.assertEqual(
            persisted.location_product_id,
            self.product.id,
            f"expected scope {self.product.id}, persisted={persisted.location_product_id}",
        )

    def test_location_product_without_a_location_is_rejected(self):
        serializer = MetaSerializer(
            data={"product": self.product.id, "location_product": self.product.id, "name": "owner", "value": "ops"},
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("location_product", serializer.errors)

    def test_location_product_that_does_not_reference_the_location_is_rejected(self):
        serializer = MetaSerializer(
            data={"location": self.location.id, "location_product": self.other_product.id, "name": "owner", "value": "ops"},
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("location_product", serializer.errors)


@skip_unless_v3
class TestMetadataLocationProductAuthorization(DojoAPITestCase):

    """
    A Location is shared by every product that recorded the same value, and edit rights on
    it come from any one of those products. The product a metadata entry is scoped to
    (``location_product``) must be authorized on its own, or a user of one asset could write
    or change metadata scoped to another asset that shares the location.
    """

    @classmethod
    def setUpTestData(cls):
        prod_type = Product_Type.objects.create(name="Meta Loc Authz PT")
        writer_role = Role.objects.get(id=Roles.Writer)
        cls.product_a = Product.objects.create(name="Meta Loc Authz A", description="A", prod_type=prod_type)
        cls.product_b = Product.objects.create(name="Meta Loc Authz B", description="B", prod_type=prod_type)

        # Alice is authorized only for Product A. Legacy authorization is membership-based
        # via authorized_users, so mirror the Product_Member row onto that M2M.
        cls.alice = User.objects.create_user(
            username="meta_loc_authz_alice",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
        )
        Product_Member.objects.create(user=cls.alice, product=cls.product_a, role=writer_role)
        cls.product_a.authorized_users.add(Dojo_User.objects.get(pk=cls.alice.pk))

        # One location recorded by both products, so Alice can edit it through Product A.
        cls.shared_location = URL.create_location_from_value("https://shared-meta.example.test/").location
        for product in (cls.product_a, cls.product_b):
            LocationProductReference.objects.create(
                location=cls.shared_location, product=product, status=ProductLocationStatus.Active,
            )
        cls.meta_b = DojoMeta.objects.create(
            location=cls.shared_location, location_product=cls.product_b, name="owner", value="team-b",
        )

    def setUp(self):
        super().setUp()
        self.client.force_authenticate(user=self.alice)

    def test_create_scoped_to_an_unauthorized_product_is_denied(self):
        response = self.client.post(
            reverse("metadata-list"),
            {"location": self.shared_location.id, "location_product": self.product_b.id, "name": "env", "value": "x"},
            format="json", secure=True,
        )
        self.assertEqual(403, response.status_code, response.content)
        self.assertFalse(DojoMeta.objects.filter(location_product=self.product_b, name="env").exists())

    def test_create_scoped_to_an_authorized_product_is_allowed(self):
        response = self.client.post(
            reverse("metadata-list"),
            {"location": self.shared_location.id, "location_product": self.product_a.id, "name": "env", "value": "x"},
            format="json", secure=True,
        )
        self.assertEqual(201, response.status_code, response.content)
        self.assertTrue(DojoMeta.objects.filter(location_product=self.product_a, name="env").exists())

    # The OSS dojo_meta queryset does not list location metadata for non-superusers, so a
    # detail request 404s before the object check runs. A queryset that does expose rows by
    # location (an auth filter plugin) leaves the object check as the only guard, so test it
    # directly.
    def _object_permission(self, method):
        request = getattr(APIRequestFactory(), method)("/api/v2/metadata/")
        request.user = self.alice
        return UserHasDojoMetaPermission().has_object_permission(request, None, self.meta_b)

    def test_object_permission_denies_update_of_an_entry_scoped_to_an_unauthorized_product(self):
        self.assertFalse(self._object_permission("patch"))
        self.assertFalse(self._object_permission("put"))

    def test_object_permission_denies_delete_of_an_entry_scoped_to_an_unauthorized_product(self):
        self.assertFalse(self._object_permission("delete"))
