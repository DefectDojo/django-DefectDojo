from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from dojo.models import Finding, User
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient


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

