import json
from os import path
from unittest import mock

from django.test import TestCase
from dojo.models import (Engagement, Product, Test, Tool_Configuration,
                         Tool_Type)
from dojo.tools.sonarqube_api.importer import SonarQubeApiImporter


class TestSonarqubeImporter(TestCase):

    def setUp(self):
        tool_type = Tool_Type.objects.create(name='SonarQube')
        Tool_Configuration.objects.create(name='SonarQube', tool_type=tool_type, authentication_type="API")

        product = Product(name='product')
        engagement = Engagement(product=product)
        self.test = Test(
            engagement=engagement
        )

    def dummy_product(self, *args, **kwargs):
        with open(path.join(path.dirname(__file__), "scans/sonarqube_api/product.json")) as json_file:
            data = json.load(json_file)
            return data

    def dummy_issues(self, *args, **kwargs):
        with open(path.join(path.dirname(__file__), "scans/sonarqube_api/issues.json")) as json_file:
            data = json.load(json_file)
            return data

    def dummy_rule(self, *args, **kwargs):
        with open(path.join(path.dirname(__file__), "scans/sonarqube_api/rule.json")) as json_file:
            data = json.load(json_file)
            return data

    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_project', dummy_product)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_rule', dummy_rule)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_issues', dummy_issues)
    def test_parse_file_with_one_cwe_and_one_no_cwe_vulns(self):
        parser = SonarQubeApiImporter()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(2, len(findings))
