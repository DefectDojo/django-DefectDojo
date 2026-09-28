"""
Regression tests for information disclosure through the scan-import permission classes.

The import permission classes resolve caller-supplied names against unscoped managers
before any authorization call runs. A mismatch between the supplied product type name
and the stored one must not put the stored name into the error body, because the caller
reaching that branch may hold no grant on the resolved product at all.
"""
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.models import Dojo_User, Product, Product_Type

from .dojo_test_case import DojoTestCase

SECRET_PRODUCT_TYPE_NAME = "Confidential Tenant Name Sentinel"


class TestImportErrorDisclosure(DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        cls.product_type = Product_Type.objects.create(name=SECRET_PRODUCT_TYPE_NAME)
        cls.product = Product.objects.create(
            name="Import Disclosure Victim Product",
            description="victim",
            prod_type=cls.product_type,
        )
        # No Product_Member, no Product_Type_Member, no staff, no superuser.
        cls.outsider = Dojo_User.objects.create_user(
            username="import_disclosure_outsider", is_active=True,
        )
        cls.token = Token.objects.create(user=cls.outsider)

    def _client(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Token {self.token.key}")
        return client

    def _payload(self):
        return {
            "scan_type": "Generic Findings Import",
            "product_name": self.product.name,
            "product_type_name": "a name the caller guessed wrong",
            "engagement_name": "an engagement that does not exist",
        }

    def _assert_no_disclosure(self, response):
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(SECRET_PRODUCT_TYPE_NAME, response.content.decode())

    def test_outsider_cannot_read_the_product_type(self):
        response = self._client().get(f"/api/v2/product_types/{self.product_type.id}/")
        self.assertEqual(response.status_code, 404)

    def test_import_scan_does_not_disclose_product_type_name(self):
        self._assert_no_disclosure(
            self._client().post("/api/v2/import-scan/", self._payload()),
        )

    def test_reimport_scan_does_not_disclose_product_type_name(self):
        self._assert_no_disclosure(
            self._client().post("/api/v2/reimport-scan/", self._payload()),
        )

    def test_endpoint_meta_import_does_not_disclose_product_type_name(self):
        payload = self._payload()
        payload.pop("scan_type")
        payload.pop("engagement_name")
        self._assert_no_disclosure(
            self._client().post("/api/v2/endpoint_meta_import/", payload),
        )
