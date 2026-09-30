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

from dojo.api_v2.serializers import MetaSerializer
from dojo.models import DojoMeta, Product, Product_Type
from dojo.url.models import URL

from .dojo_test_case import DojoTestCase


@patch("dojo.api_v2.serializers.locations_enabled", new=lambda: True)
class TestMetaSerializerLocation(DojoTestCase):
    @classmethod
    def setUpTestData(cls):
        cls.product_type = Product_Type.objects.create(name="Meta Loc PT")
        cls.product = Product.objects.create(name="Meta Loc Product", description="p", prod_type=cls.product_type)
        cls.location = URL.get_or_create_from_values(
            protocol="https", host="meta-location.example.test", path=""
        ).location

    def test_location_only_payload_is_valid(self):
        serializer = MetaSerializer(data={"location": self.location.id, "name": "environment", "value": "prod"})
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.validated_data["location"], self.location)

    def test_endpoint_key_still_maps_to_location(self):
        # Legacy clients name the location through ``endpoint``; that compatibility stays.
        serializer = MetaSerializer(data={"endpoint": self.location.id, "name": "environment", "value": "prod"})
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.validated_data["location"], self.location)

    def test_location_product_scope_is_persisted(self):
        serializer = MetaSerializer(
            data={"location": self.location.id, "location_product": self.product.id, "name": "owner", "value": "ops"}
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
            data={"product": self.product.id, "location_product": self.product.id, "name": "owner", "value": "ops"}
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("location_product", serializer.errors)
