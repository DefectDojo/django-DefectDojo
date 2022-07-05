import json
from unittest import mock

from dojo.tools.sonarqube_api.parser import SonarQubeAPIParser
from ..dojo_test_case import DojoTestCase
from dojo.models import Tool_Type, Tool_Configuration, Product_Type, Product, Engagement, Test


def dummy_product(self, *args, **kwargs):
    with open("unittests/scans/sonarqube_api/product.json") as json_file:
        data = json.load(json_file)
        return data


def dummy_issues(self, *args, **kwargs):
    with open("unittests/scans/sonarqube_api/issues.json") as json_file:
        data = json.load(json_file)
        return data


def dummy_rule(self, *args, **kwargs):
    with open("unittests/scans/sonarqube_api/rule.json") as json_file:
        data = json.load(json_file)
        return data


def dummy_hotspot_rule(self, *args, **kwargs):
    with open(get_unit_tests_path() + '/scans/sonarqube_api/hotspots/rule.json') as json_file:
        data = json.load(json_file)
        return data


def empty_list(self, *args, **kwargs):
    return list()


class TestSonarqubeApiParser(DojoTestCase):
    def setUp(self):
        product_type, _ = Product_Type.objects.get_or_create(name="Fake unit tests")
        product, _ = Product.objects.get_or_create(name="product", prod_type=product_type)
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)
        # build Sonarqube conf (the parser need it)
        tool_type, _ = Tool_Type.objects.get_or_create(name="SonarQube")
        tool_conf, _ = Tool_Configuration.objects.get_or_create(
            name="SQ1_unittests", authentication_type="API", tool_type=tool_type
        )

    @mock.patch("dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_project", dummy_product)
    @mock.patch("dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_rule", dummy_rule)
    @mock.patch("dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_issues", dummy_issues)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_hotspot_rule', dummy_hotspot_rule)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_hotspots', empty_list)
    def test_get_findings(self):
        parser = SonarQubeAPIParser()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(2, len(findings))
