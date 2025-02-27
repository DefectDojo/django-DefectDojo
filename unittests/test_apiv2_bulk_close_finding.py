from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from dojo.models import Finding, User
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase


class BulkCloseFindingsTestCase(APITestCase):

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        self.url = reverse('finding-bulk-close')

    def test_bulk_close_findings(self):
        findings = Finding.objects.filter(active=True).values_list("id", flat=True)
        data = {
           "findings": []
        }
        for finding_id in findings:
            finding_request = {
                "id": finding_id,
                "is_mitigated": True,
                "mitigated": "2025-02-27",
            }
            data["findings"].append(finding_request)
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        for finding_data in data["findings"]:
            finding_id = Finding.objects.get(id=finding_data["id"])
            self.assertTrue(finding_id.is_mitigated)
            self.assertEqual(finding_id.mitigated.strftime('%Y-%m-%d'), finding_data["mitigated"])
            self.assertFalse(finding_id.active)

    def test_bulk_close_invalid_data(self):
        # id not found
        data = {
            "findings": [
                {
                    "id": 999,
                    "is_mitigated": True,
                    "mitigated": "2025-02-27",
                }
            ]
        }
        
        response = self.client.post(self.url, data, format='json')
        
        self.assertEqual(response.code, status.HTTP_400_BAD_REQUEST)

    # def test_bulk_close_missing_fields(self):
    #     data = {
    #         "findings": [
    #             {
    #                 "id": 10,
    #                 "is_mitigated": True,
    #                 # Falta el campo "mitigated"
    #                 "message": "close for test"
    #             }
    #         ]
    #     }
        
    #     response = self.client.post(self.url, data, format='json')
        
    #     self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
