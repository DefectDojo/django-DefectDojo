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
                "id": int(finding_id),
                "is_mitigated": True,
                "mitigated": "2025-02-27",
            }
            data["findings"].append(finding_request)
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        
        for finding_data in data["findings"]:
            finding = Finding.objects.get(id=finding_data["id"])
            self.assertTrue(finding.is_mitigated)
            self.assertEqual(finding.mitigated.strftime('%Y-%m-%d'), finding_data["mitigated"])
            self.assertFalse(finding.active)

    def test_bulk_close_verify(self):
        data = {
            "verify": True,
            "findings": [
                {
                    "id": 999,
                    "is_mitigated": True,
                    "mitigated": "2025-02-27",
                },
                {
                    "id": 2,
                    "is_mitigated": True,
                    "mitigated": "2025-02-27",
                },
                {
                    "id": 22,
                    "is_mitigated": True,
                    "mitigated": "2025-02-27",
                },
                {
                    "id": 124,
                    "is_mitigated": True,
                    "mitigated": "2025-02-27",
                }
            ]
        }
        
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["data"]["success"], [
            {2: 'closed succesfully'},
            {22: 'closed succesfully'},
            {124: 'closed succesfully'}
            ])
        self.assertEqual(response.data["data"]["errors"], [{999: 'not found'}])