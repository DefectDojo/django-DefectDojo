import json
from django.test import TestCase
from unittest.mock import patch
from django.core.exceptions import ValidationError

from dojo.models import Test, Engagement, Product, Product_API_Scan_Configuration, Tool_Type, Tool_Configuration
from dojo.tools.api_msdefender.importer import MSDefenderApiImporter


class TestMSDefendermporter(TestCase):

    @classmethod
    def setUpTestData(cls):

        cls.tool_type = Tool_Type()
        cls.tool_configuration = Tool_Configuration()
        cls.tool_configuration.tool_type = cls.tool_type
        cls.tool_configuration.authentication_type = 'Password'
        cls.tool_configuration.username = 'client_id'
        cls.tool_configuration.password = 'client_password'
        cls.tool_configuration.extras = '{"extras": "tenant_id"}'

        cls.product = Product()
        cls.product.name = 'Product'
        cls.engagement = Engagement()
        cls.engagement.product = cls.product
        cls.test = Test()
        cls.test.engagement = cls.engagement

        # This API Scan configuration is not connected to a test
        cls.api_scan_configuration = Product_API_Scan_Configuration()
        cls.api_scan_configuration.product = cls.product
        cls.api_scan_configuration.tool_configuration = cls.tool_configuration

        cls.product_2 = Product()
        cls.product_2.name = 'Product_2'
        cls.engagement_2 = Engagement()
        cls.engagement_2.product = cls.product_2
        cls.test_2 = Test()
        cls.test_2.engagement = cls.engagement_2

        # This API Scan Configuration is connected with test_2
        cls.api_scan_configuration_2 = Product_API_Scan_Configuration()
        cls.test_2.api_scan_configuration = cls.api_scan_configuration_2
        cls.api_scan_configuration_2.product = cls.product_2
        cls.api_scan_configuration_2.tool_configuration = cls.tool_configuration
        cls.api_scan_configuration_2.service_key_1 = 'SERVICE_KEY_1'

        cls.findings = json.dumps({'a': 1, 'b': 2})

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

    @patch('dojo.models.Product_API_Scan_Configuration.objects')
    def test_prepare_client_one_product_configuration(self, mock_foo):
        mock_foo.filter.return_value = mock_foo
        mock_foo.count.return_value = 1
        mock_foo.first.return_value = self.api_scan_configuration

        msdefender_importer = MSDefenderApiImporter()
        api_scan_configuration = msdefender_importer.prepare_client(self.test)

        mock_foo.filter.assert_called_with(product=self.product)
        self.assertEqual(api_scan_configuration, self.api_scan_configuration)

    def test_prepare_client_one_test_configuration(self):
        msdefender_importer = MSDefenderApiImporter()
        api_scan_configuration = msdefender_importer.prepare_client(self.test_2)

        self.assertEqual(api_scan_configuration, self.api_scan_configuration_2)

    @patch('dojo.tools.api_msdefender.importer.MSDefenderApiImporter.get_findings')
    def test_get_findings(self, mock_foo):
        mock_foo.return_value = self.findings

        msdefender_importer = MSDefenderApiImporter()
        my_findings = msdefender_importer.get_findings(self.test_2)

        mock_foo.assert_called_with('SERVICE_KEY_1')
        self.assertEqual(my_findings, self.findings)
