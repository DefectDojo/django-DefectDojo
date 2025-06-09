from datetime import datetime
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from dojo.models import Finding, User
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient
from dojo.api_v2.metrics.helper import apply_filter


class MetricIARecommendationApiViewTestCase(APITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        self.url = reverse('metrics')

        self.user = User.objects.get(username="admin")
        findings = Finding.objects.all()
        self.finding1 = findings[0]
        self.finding2 = findings[1]
        self.data_ia_recommendation = {
            "data": {
                "last_modified": "2025-06-04",
                "user": "admin",
                "like_status": True,
                "mitigations": [
                    "mitigation Test"
                ],
                "files_to_fix": [
                    "Dockerfile"
                ],
                "recommendations": [
                    "recommendation Test"
                ]
            },
            "status": "Success"
        }

    def test_get_metrics_ia_recommendation_success(self):
        """Test successful retrieval of IA recommendation metrics"""
        self.finding1.ia_recommendation = self.data_ia_recommendation
        self.finding1.save()
        response = self.client.get(self.url,
                                   self.data_ia_recommendation,
                                   format='json')
        self.assertEqual(response.status_code,
                         status.HTTP_200_OK,
                         response.data)
        self.assertIn("interaction_counter", response.data["results"])
        self.assertIn("like_counter", response.data["results"])
        self.assertIn("dislike_counter", response.data["results"])
        self.assertIn("users", response.data["results"])
        # like general
        self.assertEqual(1, response.data["results"]["interaction_counter"])
        self.assertEqual(1, response.data["results"]["like_counter"])
        self.assertEqual(0, response.data["results"]["dislike_counter"])
        # like for user
        self.assertEqual(1, response.data["results"]["users"][0]["interaction_counter"])
        self.assertEqual(1, response.data["results"]["users"][0]["like_counter"])
        self.assertEqual(0, response.data["results"]["users"][0]["dislike_counter"])

    def test_get_metrics_ia_recommendation_dislikes(self):
        self.finding1.ia_recommendation = self.data_ia_recommendation
        self.finding1.ia_recommendation["data"]["like_status"] = False
        self.finding1.save()
        response = self.client.get(self.url,
                                   self.data_ia_recommendation,
                                   format='json')
        self.assertEqual(response.status_code,
                         status.HTTP_200_OK,
                         response.data)
        self.assertIn("interaction_counter", response.data["results"])
        self.assertIn("like_counter", response.data["results"])
        self.assertIn("dislike_counter", response.data["results"])
        self.assertIn("users", response.data["results"])
        # like general
        self.assertEqual(1, response.data["results"]["interaction_counter"])
        self.assertEqual(0, response.data["results"]["like_counter"])
        self.assertEqual(1, response.data["results"]["dislike_counter"])
        # like for user
        self.assertEqual(1, response.data["results"]["users"][0]["interaction_counter"])
        self.assertEqual(1, response.data["results"]["users"][0]["dislike_counter"])
        self.assertEqual(0, response.data["results"]["users"][0]["like_counter"])

    def test_get_metrics_ia_recommendation_like_and_dislike(self):
        self.finding1.ia_recommendation = self.data_ia_recommendation
        self.finding1.ia_recommendation["data"]["like_status"] = True
        self.finding1.save()
        self.finding2.ia_recommendation = self.data_ia_recommendation
        self.finding2.ia_recommendation["data"]["like_status"] = False
        self.finding2.save()
        response = self.client.get(self.url,
                                   self.data_ia_recommendation,
                                   format='json')
        self.assertEqual(response.status_code,
                         status.HTTP_200_OK,
                         response.data)
        self.assertIn("interaction_counter", response.data["results"])
        self.assertIn("like_counter", response.data["results"])
        self.assertIn("dislike_counter", response.data["results"])
        self.assertIn("users", response.data["results"])
        # like general
        self.assertEqual(2, response.data["results"]["interaction_counter"])
        self.assertEqual(1, response.data["results"]["like_counter"])
        self.assertEqual(1, response.data["results"]["dislike_counter"])
        # like for user
        self.assertEqual(2, response.data["results"]["users"][0]["interaction_counter"])
        self.assertEqual(1, response.data["results"]["users"][0]["like_counter"])
        self.assertEqual(1, response.data["results"]["users"][0]["dislike_counter"])

    def test_apply_filter_within_date_range(self):
        self.finding1.ia_recommendation = self.data_ia_recommendation
        self.finding1.ia_recommendation["data"]["last_modified"] = "2025-05-15"
        self.finding1.save()
        """Test filtering when the date is within the range"""
        start_date = datetime.strptime("2025-05-01", "%Y-%m-%d").date()
        end_date = datetime.strptime("2025-06-30", "%Y-%m-%d").date()
        result = apply_filter(self.finding1,
                              start_date=start_date,
                              end_date=end_date)
        self.assertTrue(result)

    def test_apply_filter_outside_date_range(self):
        """Test filtering when the date is outside the range"""
        self.finding1.ia_recommendation = self.data_ia_recommendation
        self.finding1.ia_recommendation["data"]["last_modified"] = "2025-05-15"
        self.finding1.save()
        start_date = datetime.strptime("2025-07-01", "%Y-%m-%d").date()
        end_date = datetime.strptime("2025-07-30", "%Y-%m-%d").date()
        result = apply_filter(self.finding1, start_date=start_date, end_date=end_date)
        self.assertFalse(result)

    def test_apply_filter_only_start_date(self):
        """Test filtering with only a start date"""
        self.finding1.ia_recommendation = self.data_ia_recommendation
        self.finding1.ia_recommendation["data"]["last_modified"] = "2025-05-15"
        self.finding1.save()
        start_date = datetime.strptime("2025-05-01", "%Y-%m-%d").date()
        result = apply_filter(self.finding1, start_date=start_date)
        self.assertTrue(result)

    def test_apply_filter_only_end_date(self):
        """Test filtering with only an end date"""
        self.finding1.ia_recommendation = self.data_ia_recommendation
        self.finding1.ia_recommendation["data"]["last_modified"] = "2025-05-15"
        self.finding1.save()
        end_date = datetime.strptime("2025-05-30", "%Y-%m-%d").date()
        result = apply_filter(self.finding1, end_date=end_date)
        self.assertTrue(result)

    def test_apply_filter_no_dates(self):
        """Test filtering with no dates provided"""
        self.finding1.ia_recommendation = self.data_ia_recommendation
        self.finding1.ia_recommendation["data"]["last_modified"] = "2025-05-15"
        self.finding1.save()
        result = apply_filter(self.finding1)
        self.assertTrue(result)

    def test_apply_filter_invalid_date_format(self):
        """Test filtering with an invalid date format in the finding"""
        self.finding1.ia_recommendation = self.data_ia_recommendation
        self.finding1.ia_recommendation["data"]["last_modified"] = "2025-05-15"
        self.finding1.save()
        self.finding1.ia_recommendation["data"]["last_modified"] = "invalid-date"
        start_date = datetime.strptime("2025-05-01", "%Y-%m-%d").date()
        end_date = datetime.strptime("2025-06-30", "%Y-%m-%d").date()
        result = apply_filter(self.finding1, start_date=start_date, end_date=end_date)
        self.assertFalse(result)

