"""
Tests for the editable Asset attribute lookup tables (platform/lifecycle/origin).

Covers the models and their seeded defaults, the /api/v2 CRUD endpoints (including the immutability
of ``value``), and that the Product API keeps exposing/accepting the option's ``value`` string via
SlugRelatedField after the CharField -> ForeignKey conversion.
"""
from django.test import override_settings
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.models import Product, Product_Lifecycle, Product_Origin, Product_Platform, Product_Type, SLA_Configuration
from unittests.dojo_test_case import DojoAPITestCase, versioned_fixtures


@versioned_fixtures
@override_settings(SECURE_SSL_REDIRECT=False)
class ProductAttributeModelTest(DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]

    def test_defaults_are_seeded(self):
        self.assertEqual(Product_Platform.objects.filter(value="web service").first().name, "API")
        self.assertEqual(Product_Lifecycle.objects.filter(value="production").count(), 1)
        self.assertEqual(Product_Origin.objects.filter(value="internal").first().name, "Internally Developed")


@versioned_fixtures
@override_settings(SECURE_SSL_REDIRECT=False)
class ProductAttributeApiTest(DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

    def test_list_platforms(self):
        response = self.client.get("/api/v2/product_platforms/", format="json")
        self.assertEqual(response.status_code, 200, response.content[:500])
        values = {row["value"] for row in response.json()["results"]}
        self.assertIn("web service", values)

    def test_create_and_value_immutable(self):
        created = self.client.post(
            "/api/v2/product_lifecycles/",
            data={"value": "beta", "name": "Beta"}, format="json",
        )
        self.assertEqual(created.status_code, 201, created.content[:500])
        option_id = created.json()["id"]
        # value is immutable on update; only the label changes.
        updated = self.client.patch(
            f"/api/v2/product_lifecycles/{option_id}/",
            data={"name": "Beta Renamed", "value": "gamma"}, format="json",
        )
        self.assertEqual(updated.status_code, 200, updated.content[:500])
        option = Product_Lifecycle.objects.get(id=option_id)
        self.assertEqual(option.name, "Beta Renamed")
        self.assertEqual(option.value, "beta")

    def test_product_exposes_and_accepts_value_string(self):
        prod_type = Product_Type.objects.first()
        sla = SLA_Configuration.objects.first()
        # Write path: the API accepts the option's value string.
        response = self.client.post(
            reverse("product-list"),
            data={
                "name": "pa-wire-compat", "description": "d",
                "prod_type": prod_type.id, "sla_configuration": sla.id,
                "platform": "web", "lifecycle": "production", "origin": "internal",
            },
            format="json",
        )
        self.assertEqual(response.status_code, 201, response.content[:1000])
        body = response.json()
        # Read path: the value string comes back unchanged.
        self.assertEqual(body["platform"], "web")
        self.assertEqual(body["lifecycle"], "production")
        self.assertEqual(body["origin"], "internal")
        product = Product.objects.get(id=body["id"])
        self.assertEqual(product.platform.value, "web")

    def test_unknown_value_is_rejected(self):
        prod_type = Product_Type.objects.first()
        sla = SLA_Configuration.objects.first()
        response = self.client.post(
            reverse("product-list"),
            data={
                "name": "pa-bad", "description": "d",
                "prod_type": prod_type.id, "sla_configuration": sla.id,
                "platform": "does-not-exist",
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400, response.content[:500])

    def test_delete_in_use_option_is_blocked(self):
        prod_type = Product_Type.objects.first()
        platform = Product_Platform.objects.create(value="in-use", name="In Use")
        Product.objects.create(name="pa-blocks-delete", description="d", prod_type=prod_type, platform=platform)
        response = self.client.delete(f"/api/v2/product_platforms/{platform.id}/")
        self.assertGreaterEqual(response.status_code, 400)
        self.assertTrue(Product_Platform.objects.filter(id=platform.id).exists())
