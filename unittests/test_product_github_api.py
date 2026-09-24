from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.github.models import GITHUB_Conf, GITHUB_PKey
from dojo.models import Product, User
from unittests.dojo_test_case import DojoAPITestCase, versioned_fixtures


@versioned_fixtures
class ProductGithubApiTest(DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        user = User.objects.get(username="admin")
        token = Token.objects.get(user=user)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        self.url = reverse("product-list")
        self.github_configuration = GITHUB_Conf.objects.create(
            configuration_name="Product API GitHub configuration",
            api_key="not-a-real-secret",
        )

    def test_create_product_with_github_settings(self):
        response = self.client.post(
            self.url,
            {
                "name": "Product with GitHub settings",
                "description": "Created through the product API",
                "prod_type": 1,
                "github_project": "DefectDojo/django-DefectDojo",
                "github_configuration": self.github_configuration.id,
            },
            format="json",
        )

        self.assertEqual(201, response.status_code, response.content[:1000])
        github_settings = GITHUB_PKey.objects.get(product_id=response.data["id"])
        self.assertEqual("DefectDojo/django-DefectDojo", github_settings.git_project)
        self.assertEqual(self.github_configuration, github_settings.git_conf)

    def test_create_product_without_github_settings(self):
        response = self.client.post(
            self.url,
            {
                "name": "Product without GitHub settings",
                "description": "Created through the product API",
                "prod_type": 1,
            },
            format="json",
        )

        self.assertEqual(201, response.status_code, response.content[:1000])
        self.assertFalse(GITHUB_PKey.objects.filter(product_id=response.data["id"]).exists())

    def test_create_product_rejects_unknown_github_configuration(self):
        product_name = "Product with unknown GitHub configuration"
        response = self.client.post(
            self.url,
            {
                "name": product_name,
                "description": "Created through the product API",
                "prod_type": 1,
                "github_project": "DefectDojo/django-DefectDojo",
                "github_configuration": 999999,
            },
            format="json",
        )

        self.assertEqual(400, response.status_code, response.content[:1000])
        self.assertFalse(Product.objects.filter(name=product_name).exists())
