"""
Regression tests: the scan-import permission checks must authorize the product the import writes to.

The permission classes read the raw request, while the import runs on the serializer's
validated data. Both have to resolve the same target product and engagement.
"""
import datetime
import json

from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.models import Development_Environment, Dojo_User, Engagement, Finding, Product, Product_Type, Test, Test_Type

from .dojo_test_case import DojoTestCase

SCAN_TYPE = "Generic Findings Import"


class TestImportTargetAuthorization(DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        today = datetime.date(2026, 11, 13)
        cls.member = Dojo_User.objects.create_user(username="import_target_member", is_active=True)
        cls.token = Token.objects.create(user=cls.member)

        cls.own_product = Product.objects.create(
            name="Import Target Own Product",
            description="own",
            prod_type=Product_Type.objects.create(name="Import Target Own Type"),
        )
        cls.own_product.authorized_users.add(cls.member)
        cls.own_engagement = Engagement.objects.create(
            name="Import Target Own Engagement", product=cls.own_product, target_start=today, target_end=today,
        )
        Development_Environment.objects.get_or_create(name="Development")
        test_type = Test_Type.objects.get_or_create(name=SCAN_TYPE)[0]
        cls.own_test = Test.objects.create(
            engagement=cls.own_engagement,
            test_type=test_type,
            scan_type=SCAN_TYPE,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

        cls.other_product = Product.objects.create(
            name="Import Target Other Product",
            description="other",
            prod_type=Product_Type.objects.create(name="Import Target Other Type"),
        )
        other_engagement = Engagement.objects.create(
            name="Import Target Other Engagement", product=cls.other_product, target_start=today, target_end=today,
        )
        cls.other_test = Test.objects.create(
            engagement=other_engagement,
            test_type=test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        cls.other_finding = Finding.objects.create(
            test=cls.other_test, title="Import Target Other Finding", severity="High", description="other",
            reporter=cls.member, active=True,
        )

    def _post(self, path, file, **fields):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Token {self.token.key}")
        return client.post(f"/api/v2/{path}/", {"file": file, **fields}, format="multipart")

    def _import(self, findings, **fields):
        report = json.dumps({"findings": findings}).encode()
        return self._post(
            "import-scan",
            SimpleUploadedFile("report.json", report, "application/json"),
            scan_type=SCAN_TYPE,
            auto_create_context=True,
            **fields,
        )

    def _reimport(self, **fields):
        report = json.dumps({"findings": [{"title": "again", "severity": "Low", "description": "x", "date": "2026-11-13"}]}).encode()
        return self._post(
            "reimport-scan",
            SimpleUploadedFile("report.json", report, "application/json"),
            scan_type=SCAN_TYPE,
            engagement_name=self.own_engagement.name,
            **fields,
        )

    def _import_into_other_product(self, findings, **fields):
        return self._import(
            findings,
            engagement_id=self.own_engagement.id,
            engagement_name=self.own_engagement.name,
            product_name=f" {self.other_product.name}",
            **fields,
        )

    def test_own_engagement_id_does_not_authorize_an_import_into_another_product(self):
        response = self._import_into_other_product(
            [{"title": "planted", "severity": "High", "description": "x", "date": "2026-11-13"}],
        )
        self.assertEqual(response.status_code, 403, response.content[:500])
        self.assertFalse(Engagement.objects.filter(product=self.other_product, name=self.own_engagement.name).exists())

    def test_close_old_findings_cannot_reach_another_product(self):
        response = self._import_into_other_product(
            [], close_old_findings=True, close_old_findings_product_scope=True,
        )
        self.assertEqual(response.status_code, 403, response.content[:500])
        self.other_finding.refresh_from_db()
        self.assertTrue(self.other_finding.active)
        self.assertFalse(self.other_finding.is_mitigated)

    def test_endpoint_meta_import_checks_the_product_it_writes_to(self):
        response = self._post(
            "endpoint_meta_import",
            SimpleUploadedFile("meta.csv", b"hostname,team\nimport-target.example.com,own\n", "text/csv"),
            product_name=f" {self.other_product.name}",
            product=self.own_product.id,
        )
        self.assertEqual(response.status_code, 403, response.content[:500])

    def test_padded_name_of_own_product_imports_into_own_engagement(self):
        response = self._import(
            [{"title": "own", "severity": "Low", "description": "x", "date": "2026-11-13"}],
            engagement_name=self.own_engagement.name,
            product_name=f" {self.own_product.name}",
        )
        self.assertEqual(response.status_code, 201, response.content[:500])
        self.assertEqual(response.json()["engagement_id"], self.own_engagement.id)

    def test_padded_name_of_own_product_reimports_into_own_test(self):
        response = self._reimport(product_name=f" {self.own_product.name}")
        self.assertEqual(response.status_code, 201, response.content[:500])
        self.assertEqual(response.json()["test_id"], self.own_test.id)

    def test_reimport_ignores_test_id(self):
        response = self._reimport(product_name=self.own_product.name, test_id=self.other_test.id)
        self.assertEqual(response.status_code, 201, response.content[:500])
        self.assertEqual(response.json()["test_id"], self.own_test.id)

    def test_endpoint_meta_import_ignores_product_id(self):
        response = self._post(
            "endpoint_meta_import",
            SimpleUploadedFile("meta.csv", b"hostname,team\nimport-target.example.com,own\n", "text/csv"),
            product_id=self.own_product.id,
        )
        self.assertEqual(response.status_code, 400, response.content[:500])
