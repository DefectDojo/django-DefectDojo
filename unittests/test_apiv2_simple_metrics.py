from django.urls import reverse
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from unittests.dojo_test_case import DojoAPITestCase


class SimpleMetricsAPITest(DojoAPITestCase):

    """Test the Simple Metrics APIv2 endpoint."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

    def test_simple_metrics_get(self):
        """Test GET request to simple metrics endpoint"""
        r = self.client.get(reverse("simple_metrics-list"), format="json")
        self.assertEqual(r.status_code, 200)
        # Check that it returns a list
        self.assertIsInstance(r.json(), list)

    def test_simple_metrics_get_with_date(self):
        """Test GET request with date parameter"""
        # Test with current month/year
        current_date = timezone.now().strftime('%Y-%m-%d')
        r = self.client.get(
            reverse("simple_metrics-list"),
            {"date": current_date},
            format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), list)

    def test_simple_metrics_get_with_invalid_date(self):
        """Test GET request with invalid date parameter"""
        r = self.client.get(
            reverse("simple_metrics-list"),
            {"date": "invalid-date"},
            format="json"
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn("error", r.json())

    def test_simple_metrics_response_structure(self):
        """Test that response has expected structure"""
        r = self.client.get(reverse("simple_metrics-list"), format="json")
        self.assertEqual(r.status_code, 200)
        
        data = r.json()
        if data:  # If there's any data
            # Check first item structure
            item = data[0]
            expected_fields = [
                'product_type_id', 'product_type_name', 'Total',
                'S0', 'S1', 'S2', 'S3', 'S4',
                'Opened', 'Closed'
            ]
            for field in expected_fields:
                self.assertIn(field, item)
                # Numeric fields should be integers
                if field in ['product_type_id', 'Total', 'S0', 'S1', 
                           'S2', 'S3', 'S4', 'Opened', 'Closed']:
                    self.assertIsInstance(item[field], int)

    def test_simple_metrics_post_not_allowed(self):
        """Test that POST method is not allowed"""
        r = self.client.post(reverse("simple_metrics-list"), {}, format="json")
        self.assertEqual(r.status_code, 405)  # Method not allowed

    def test_simple_metrics_with_specific_month(self):
        """Test with a specific month/year"""
        # Test with January 2024
        r = self.client.get(
            reverse("simple_metrics-list"),
            {"date": "2024-01-15"},  # Any day in January 2024
            format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json(), list)