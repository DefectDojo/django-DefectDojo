import json
from django.test import TestCase
from unittest.mock import patch

from dojo.models import Test, Engagement, Product, Product_API_Scan_Configuration, Tool_Type, Tool_Configuration
from dojo.tools.edgescan_api.importer import EdgescanApiImporter


class TestEdgescanApiImporter(TestCase):

    @classmethod
    def setUpTestData(cls):

        cls.tool_type = Tool_Type()
        cls.tool_configuration = Tool_Configuration()
        cls.tool_configuration.tool_type = cls.tool_type
        cls.tool_configuration.authentication_type = 'API'
        cls.tool_configuration.api_key = 'API_KEY'
        cls.tool_configuration.extras = 'EXTRAS'

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

        with self.assertRaisesRegex(Exception, 'API Scan Configuration for Edgescan and Product do not match.'):
            edgescan_api_importer = EdgescanApiImporter()
            edgescan_api_importer.prepare_client(test_3)

    @patch('dojo.models.Product_API_Scan_Configuration.objects')
    def test_prepare_client_more_than_one_configuration(self, mock_foo):
        mock_foo.filter.return_value = mock_foo
        mock_foo.count.return_value = 2

        with self.assertRaisesRegex(Exception, 'More than one Product API Scan Configuration has been configured, but none of them has been chosen.'):
            edgescan_api_importer = EdgescanApiImporter()
            edgescan_api_importer.prepare_client(self.test)

            mock_foo.filter.assert_called_with(product=self.product)

    @patch('dojo.models.Product_API_Scan_Configuration.objects')
    def test_prepare_client_no_configuration(self, mock_foo):
        mock_foo.filter.return_value = mock_foo
        mock_foo.count.return_value = 0

        with self.assertRaisesRegex(Exception, 'There are no API Scan Configurations for this Product.'):
            edgescan_api_importer = EdgescanApiImporter()
            edgescan_api_importer.prepare_client(self.test)

            mock_foo.filter.assert_called_with(product=self.product)

    @patch('dojo.models.Product_API_Scan_Configuration.objects')
    def test_prepare_client_one_product_configuration(self, mock_foo):
        mock_foo.filter.return_value = mock_foo
        mock_foo.count.return_value = 1
        mock_foo.first.return_value = self.api_scan_configuration

        edgescan_api_importer = EdgescanApiImporter()
        edgescan_api, api_scan_configuration = edgescan_api_importer.prepare_client(self.test)

        mock_foo.filter.assert_called_with(product=self.product)
        self.assertEqual(api_scan_configuration, self.api_scan_configuration)
        self.assertEqual(edgescan_api.api_key, 'API_KEY')

    def test_prepare_client_one_test_configuration(self):
        edgescan_api_importer = EdgescanApiImporter()
        edgescan_api, api_scan_configuration = edgescan_api_importer.prepare_client(self.test_2)

        self.assertEqual(api_scan_configuration, self.api_scan_configuration_2)
        self.assertEqual(edgescan_api.api_key, 'API_KEY')

    @patch('dojo.tools.edgescan_api.importer.EdgescanAPI.get_findings')
    def test_get_findings(self, mock_foo):
        mock_foo.return_value = self.findings

        edgescan_api_importer = EdgescanApiImporter()
        my_findings = edgescan_api_importer.get_findings(self.test_2)

        mock_foo.assert_called_with('SERVICE_KEY_1')
        self.assertEqual(my_findings, self.findings)

    # def test_get_findings_do_not_match(self):
    #     product_3 = Product()
    #     engagement_3 = Engagement()
    #     engagement_3.product = product_3
    #     test_3 = Test()
    #     test_3.engagement = engagement_3
    #     api_scan_configuration_3 = Product_API_Scan_Configuration()
    #     api_scan_configuration_3.product = self.product
    #     test_3.api_scan_configuration = api_scan_configuration_3

    #     with self.assertRaisesRegex(Exception, 'API Scan Configuration for Edgescan and Product do not match.'):
    #         edgescan_importer = EdgescanImporter()
    #         edgescan_importer.get_findings(test_3)

    # @patch('dojo.models.Product_API_Scan_Configuration.objects')
    # def test_get_findings_more_than_one_configuration(self, mock_foo):
    #     mock_foo.filter.return_value = mock_foo
    #     mock_foo.count.return_value = 2

    #     with self.assertRaisesRegex(Exception, 'More than one Product API Scan Configuration has been configured, but none of them has been chosen.'):
    #         edgescan_importer = EdgescanImporter()
    #         edgescan_importer.get_findings(self.test)

    #         mock_foo.filter.assert_called_with(product=self.product)

    # @patch('dojo.models.Product_API_Scan_Configuration.objects')
    # def test_get_findings_no_configuration(self, mock_foo):
    #     mock_foo.filter.return_value = mock_foo
    #     mock_foo.count.return_value = 0

    #     with self.assertRaisesRegex(Exception, 'There are no API Scan Configurations for this Product.'):
    #         edgescan_importer = EdgescanImporter()
    #         edgescan_importer.get_findings(self.test)

    #         mock_foo.filter.assert_called_with(product=self.product)

    # def test_get_config_scan_config_present_and_matching_product(self):
    #     product = Product()
    #     engagement = Engagement()
    #     engagement.product = product
    #     test = Test()
    #     test.engagement = engagement
    #     api_scan_configuration = Product_API_Scan_Configuration()
    #     api_scan_configuration.product = product
    #     test.api_scan_configuration = api_scan_configuration
    #     edgescan_importer = EdgescanImporter()

    #     self.assertEqual(edgescan_importer.get_config(test), api_scan_configuration)

    # def test_get_config_scan_config_present_and_no_matching_product(self):
    #     product_1 = Product()
    #     product_2 = Product()
    #     engagement = Engagement()
    #     engagement.product = product_1
    #     test = Test()
    #     test.engagement = engagement
    #     api_scan_configuration = Product_API_Scan_Configuration()
    #     api_scan_configuration.product = product_2
    #     test.api_scan_configuration = api_scan_configuration
    #     edgescan_importer = EdgescanImporter()

    #     with self.assertRaisesRegex(Exception, "API Scan Configuration for Edgescan and Product do not match."):
    #         edgescan_importer.get_config(test)

    # @patch('dojo.models.Product_API_Scan_Configuration.objects')
    # def test_get_config_scan_config_not_present_and_config_count_is_one(self, mock_foo):
    #     mock_foo.filter.return_value = mock_foo
    #     mock_foo.count.return_value = 1
        
    #     product = Product()
    #     engagement = Engagement()
    #     engagement.product = product
    #     test = Test()
    #     test.engagement = engagement
    #     api_scan_configuration = Product_API_Scan_Configuration()
    #     api_scan_configuration.product = product
    #     edgescan_importer = EdgescanImporter()

    #     mock_foo.first.return_value = api_scan_configuration

    #     self.assertEqual(edgescan_importer.get_config(test), api_scan_configuration)

    # @patch('dojo.models.Product_API_Scan_Configuration.objects')
    # def test_get_config_more_than_one_scan_config(self, mock_foo):
    #     mock_foo.filter.return_value = mock_foo
    #     mock_foo.count.return_value = 2

    #     product = Product()
    #     engagement = Engagement()
    #     engagement.product = product
    #     test = Test()
    #     test.engagement = engagement
    #     edgescan_importer = EdgescanImporter()

    #     with self.assertRaisesRegex(Exception, "More than one Product API Scan Configuration has been configured, but none of them has been chosen.\n"
    #             "Please specify at Test which one should be used."):
    #         edgescan_importer.get_config(test)

    # @patch('dojo.models.Product_API_Scan_Configuration.objects')
    # def test_get_config_no_scan_config_present(self, mock_foo):
    #     mock_foo.filter.return_value = mock_foo
    #     mock_foo.count.return_value = 0

    #     product = Product()
    #     engagement = Engagement()
    #     engagement.product = product
    #     test = Test()
    #     test.engagement = engagement
    #     edgescan_importer = EdgescanImporter()

    #     with self.assertRaisesRegex(Exception, "There are no API Scan Configurations for this Product.\n"
    #             "Please add at least one API Scan Configuration for Edgescan to this Product."):
    #         edgescan_importer.get_config(test)

    # def test_get_api_key(self):
    #     api_key = "4p1t0k3n"
    #     tool_config = Tool_Configuration()
    #     tool_config.api_key = api_key
    #     config = Product_API_Scan_Configuration()
    #     config.tool_configuration = tool_config
    #     edgescan_importer = EdgescanImporter()

    #     self.assertEqual(edgescan_importer.get_api_key(config), api_key)

    # def test_get_edgescan_url(self):
    #     url = "test.example.com"
    #     tool_config = Tool_Configuration()
    #     tool_config.url = url
    #     config = Product_API_Scan_Configuration()
    #     config.tool_configuration = tool_config
    #     edgescan_importer = EdgescanImporter()

    #     self.assertEqual(edgescan_importer.get_edgescan_url(config), url)

    # def test_get_extra_options(self):
    #     extras = '{"proxy": "test.example.com"}'
    #     tool_config = Tool_Configuration()
    #     tool_config.extras = extras
    #     config = Product_API_Scan_Configuration()
    #     config.tool_configuration = tool_config
    #     edgescan_importer = EdgescanImporter()

    #     self.assertEqual(edgescan_importer.get_extra_options(config), json.loads(extras))

    # def test_get_asset_id(self):
    #     service_key_1 = "asset ID"
    #     config = Product_API_Scan_Configuration()
    #     config.service_key_1 = service_key_1
    #     edgescan_importer = EdgescanImporter()

    #     self.assertEqual(edgescan_importer.get_asset_id(config), service_key_1)
