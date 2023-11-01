from django.test import TestCase
from unittest.mock import patch
from django.core.exceptions import ValidationError

from dojo.models import Test, Engagement, Product, Product_API_Scan_Configuration
from dojo.tools.api_msdefender.importer import MSDefenderApiImporter


class TestMSDefenderImporter(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.product = Product()
        cls.product.name = 'Product'
        cls.engagement = Engagement()
        cls.engagement.product = cls.product
        cls.test = Test()
        cls.test.engagement = cls.engagement

    def test_prepare_client_do_not_match(self):
        product_3 = Product()
        engagement_3 = Engagement()
        engagement_3.product = product_3
        test_3 = Test()
        test_3.engagement = engagement_3
        api_scan_configuration_3 = Product_API_Scan_Configuration()
        api_scan_configuration_3.product = self.product
        test_3.api_scan_configuration = api_scan_configuration_3

        with self.assertRaisesRegex(ValidationError, r'API Scan Configuration for MSDefender API and Product do not match. Product: "" \(None\), config\.product: "Product" \(None\)'):
            msdefender_importer = MSDefenderApiImporter()
            msdefender_importer.prepare_client(test_3)

    @patch('dojo.models.Product_API_Scan_Configuration.objects')
    def test_prepare_client_more_than_one_configuration(self, mock_foo):
        mock_foo.filter.return_value = mock_foo
        mock_foo.count.return_value = 2

        with self.assertRaisesRegex(ValidationError, r'More than one Product API Scan Configuration has been configured, but none of them has been chosen\.\\nPlease specify at Test which one should be used\. Product: "Product" \(None\)'):
            msdefender_importer = MSDefenderApiImporter()
            msdefender_importer.prepare_client(self.test)
            mock_foo.filter.assert_called_with(product=self.product)

    @patch('dojo.models.Product_API_Scan_Configuration.objects')
    def test_prepare_client_no_configuration(self, mock_foo):
        mock_foo.filter.return_value = mock_foo
        mock_foo.count.return_value = 0

        with self.assertRaisesRegex(ValidationError, r'There are no API Scan Configurations for this Product\.\\nPlease add at least one API Scan Configuration for MSDefender API to this Product\. Product: "Product" \(None\)'):
            msdefender_importer = MSDefenderApiImporter()
            msdefender_importer.prepare_client(self.test)
            mock_foo.filter.assert_called_with(product=self.product)
