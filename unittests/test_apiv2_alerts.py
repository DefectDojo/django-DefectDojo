from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from dojo.models import Alerts, User
from rest_framework.authtoken.models import Token

class AlertApiViewTestCase(APITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.user = User.objects.get(username="admin")
        token = Token.objects.get(user=self.user)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        self.url = reverse('alerts-list')

        Alerts.objects.create(title="Test Alert 1", user_id=self.user)
        Alerts.objects.create(title="Test Alert 2", user_id=self.user)

    def test_list_alerts_success(self):
        """Test successful retrieval of alerts list"""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertTrue(len(response.data["results"]) >= 2)
        titles = [alert["title"] for alert in response.data["results"]]
        self.assertIn("Test Alert 1", titles)
        self.assertIn("Test Alert 2", titles)

    def test_list_alerts_pagination(self):
        """Test alerts list paginated"""
        for i in range(30):
            Alerts.objects.create(title=f"Alert {i}", user_id=self.user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("results", response.data)
        self.assertIn("count", response.data)
        self.assertTrue(response.data["count"] > 2)

    def test_list_alerts_filter_by_source(self):
        """Test filtering alerts by source"""
        Alerts.objects.create(title="Source Alert", user_id=self.user, source="system")
        response = self.client.get(self.url, {"source": "system"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for alert in response.data["results"]:
            self.assertEqual(alert["source"], "system")