from django.test import TestCase
from unittest.mock import patch

from dojo.models import (
    Test,
    Engagement,
    Product,
    Product_API_Scan_Configuration,
    Tool_Type,
    Tool_Configuration,
)
from dojo.tools.bugcrowd_api.importer import BugcrowdApiImporter


class TestBugcrowdApiImporter(TestCase):
    @classmethod
    def setUpTestData(cls):

        cls.tool_type = Tool_Type()
        cls.tool_configuration = Tool_Configuration()
        cls.tool_configuration.tool_type = cls.tool_type
        cls.tool_configuration.authentication_type = "API"
        cls.tool_configuration.api_key = "API_KEY"
        cls.tool_configuration.extras = '{"extras": "EXTRAS"}'

        cls.product = Product()
        cls.product.name = "Product"
        cls.engagement = Engagement()
        cls.engagement.product = cls.product
        cls.test = Test()
        cls.test.engagement = cls.engagement

        # This API Scan configuration is not connected to a test
        cls.api_scan_configuration = Product_API_Scan_Configuration()
        cls.api_scan_configuration.product = cls.product
        cls.api_scan_configuration.tool_configuration = cls.tool_configuration

        cls.product_2 = Product()
        cls.product_2.name = "Product_2"
        cls.engagement_2 = Engagement()
        cls.engagement_2.product = cls.product_2
        cls.test_2 = Test()
        cls.test_2.engagement = cls.engagement_2

        # This API Scan Configuration is connected with test_2
        cls.api_scan_configuration_2 = Product_API_Scan_Configuration()
        cls.test_2.api_scan_configuration = cls.api_scan_configuration_2
        cls.api_scan_configuration_2.product = cls.product_2
        cls.api_scan_configuration_2.tool_configuration = cls.tool_configuration
        cls.api_scan_configuration_2.service_key_1 = "SERVICE_KEY_1"
        cls.api_scan_configuration_2.service_key_2 = "SERVICE_KEY_2"

        cls.findings = ["a", "b"]

    def test_prepare_client_do_not_match(self):
        product_3 = Product()
        engagement_3 = Engagement()
        engagement_3.product = product_3
        test_3 = Test()
        test_3.engagement = engagement_3
        api_scan_configuration_3 = Product_API_Scan_Configuration()
        api_scan_configuration_3.product = self.product
        test_3.api_scan_configuration = api_scan_configuration_3

        with self.assertRaisesRegex(
            Exception,
            "API Scan Configuration for Bugcrowd API and Product do not match.",
        ):
            bugrcrowd_api_importer = BugcrowdApiImporter()
            bugrcrowd_api_importer.prepare_client(test_3)

    @patch("dojo.models.Product_API_Scan_Configuration.objects")
    def test_prepare_client_more_than_one_configuration(self, mock_foo):
        mock_foo.filter.return_value = mock_foo
        mock_foo.count.return_value = 2

        with self.assertRaisesRegex(
            Exception,
            "More than one Product API Scan Configuration has been configured, but none of them has been chosen.",
        ):
            bugrcrowd_api_importer = BugcrowdApiImporter()
            bugrcrowd_api_importer.prepare_client(self.test)

            mock_foo.filter.assert_called_with(product=self.product)

    @patch("dojo.models.Product_API_Scan_Configuration.objects")
    def test_prepare_client_no_configuration(self, mock_foo):
        mock_foo.filter.return_value = mock_foo
        mock_foo.count.return_value = 0

        with self.assertRaisesRegex(
            Exception, "There are no API Scan Configurations for this Product."
        ):
            bugrcrowd_api_importer = BugcrowdApiImporter()
            bugrcrowd_api_importer.prepare_client(self.test)

            mock_foo.filter.assert_called_with(product=self.product)

    @patch("dojo.models.Product_API_Scan_Configuration.objects")
    def test_prepare_client_one_product_configuration(self, mock_foo):
        mock_foo.filter.return_value = mock_foo
        mock_foo.count.return_value = 1
        mock_foo.first.return_value = self.api_scan_configuration

        bugrcrowd_api_importer = BugcrowdApiImporter()
        bugcrowd_api, api_scan_configuration = bugrcrowd_api_importer.prepare_client(
            self.test
        )

        mock_foo.filter.assert_called_with(
            product=self.product, tool_configuration__tool_type__name="Bugcrowd API"
        )
        self.assertEqual(api_scan_configuration, self.api_scan_configuration)
        self.assertEqual(bugcrowd_api.api_token, "API_KEY")

    def test_prepare_client_one_test_configuration(self):
        bugrcrowd_api_importer = BugcrowdApiImporter()
        bugcrowd_api, api_scan_configuration = bugrcrowd_api_importer.prepare_client(
            self.test_2
        )

        self.assertEqual(api_scan_configuration, self.api_scan_configuration_2)
        self.assertEqual(bugcrowd_api.api_token, "API_KEY")

    @patch("dojo.tools.bugcrowd_api.importer.BugcrowdAPI.get_findings")
    def test_get_findings(self, mock_foo):
        mock_foo.return_value = self.findings

        bugrcrowd_api_importer = BugcrowdApiImporter()
        my_findings, api_scan_config = bugrcrowd_api_importer.get_findings(self.test_2)

        mock_foo.assert_called_with("SERVICE_KEY_1", "SERVICE_KEY_2")
        self.assertListEqual(my_findings, self.findings)
