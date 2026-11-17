from datetime import date

from rest_framework import status
from rest_framework.test import APIClient, APITestCase
from rest_framework.authtoken.models import Token

from dojo.models import Engagement, Product


class TestMetricsDevicesWithoutFindingsApiView(APITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        self.url = "/api/v2/metrics/devices_without_findings"
        self.product = Product.objects.first()

    def create_engagement(self, name, provider):
        return Engagement.objects.create(
            name=name,
            product=self.product,
            target_start=date.today(),
            target_end=date.today(),
            description=(
                f"PROVIDER: {provider}\n"
                f"CLASSID: class-{name}\n"
                f"ITEM: item-{name}"
            ),
        )

    def test_lists_devices_for_supported_providers(self):
        created_engagements = [
            self.create_engagement(f"device-{provider.lower()}", provider)
            for provider in ("TENABLE", "SERVERLESS", "IMAGES")
        ]

        response = self.client.get(self.url, {"limit": 1000})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results_by_name = {
            result["name"]: result for result in response.data["results"]
        }
        for engagement in created_engagements:
            result = results_by_name[engagement.name]
            self.assertEqual(
                set(result),
                {
                    "name",
                    "product_name",
                    "product_type_name",
                    "provider",
                    "class_id",
                    "item_class_id",
                },
            )
            self.assertEqual(result["provider"], engagement.provider)

    def test_provider_filter_and_validation(self):
        tenable = self.create_engagement("device-tenable", "TENABLE")
        self.create_engagement("device-images", "IMAGES")

        response = self.client.get(self.url, {"provider": "TENABLE"})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn(tenable.name, {result["name"] for result in response.data["results"]})

        response = self.client.get(self.url, {"provider": "OTHER"})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_date_filters_are_not_supported_yet(self):
        response = self.client.get(self.url, {"start_date": "2026-01-01"})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
