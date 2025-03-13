from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from dojo.models import (
    Dojo_User,
    Product_Type,
    Finding,
    TransferFinding)
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient


class TransferFindingFindingsTestCase(APITestCase):

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        self.url = reverse('transfer_finding_findings-list')

        self.origin_product_type = Product_Type.objects.get(id=2)
        self.origin_product = self.origin_product_type.prod_type.get(id=2)
        self.origin_engagement = self.origin_product.engagement_set.get(id=1)
        self.destination_product_type = Product_Type.objects.get(id=1)
        self.destination_product = self.destination_product_type.prod_type.get(id=1)
        self.destination_engagement = self.destination_product.engagement_set.get(id=2)

        self.transfer_finding = TransferFinding.objects.create(
            title="Transfer Test Title",
            date="2025-02-27",
            origin_product_type=self.origin_product_type,
            origin_product=self.origin_product,
            origin_engagement=self.origin_engagement,
            destination_product_type=self.destination_product_type,
            destination_product=self.destination_product,
            destination_engagement=self.destination_engagement,
            accepted_by=Dojo_User.objects.get(username="admin"),
            expiration_date="2025-02-27",
            expiration_date_warned="2025-02-27",
            expiration_date_handled="2025-02-27",
            reactivate_expired=False,
            restart_sla_expired=False,
            owner=Dojo_User.objects.get(username="user1"),
            notes="Transfer Test Notes")


    def test_create_transfer_finding_finding(self):
        data = {
            "transfer_findings": self.transfer_finding.id,
            "findings": [3],
            "finding_related": None
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)
        self.assertEqual(response.data["message"], "Transfer Finding Finding Created")

    def test_create_transfer_finding_finding_already_transferred(self):
        data = {
            "transfer_findings": self.transfer_finding.id,
            "findings": [3, 3],
            "finding_related": None
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_428_PRECONDITION_REQUIRED)
        self.assertEqual(110, len(response.data["error"]["detail"]))

    def test_finding_status_error(self):
        finding = Finding.objects.get(id=3)
        finding.risk_status = "Transfer Pending"
        finding.save()
        data = {
            "transfer_findings": self.transfer_finding.id,
            "findings": [3],
            "finding_related": None
        }
        response = self.client.post(self.url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_428_PRECONDITION_REQUIRED)
        self.assertEqual(53, len(response.data["error"]["detail"]))