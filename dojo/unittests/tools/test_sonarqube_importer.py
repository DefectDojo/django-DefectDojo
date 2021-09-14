import json
from unittest import mock

from dojo.tools.sonarqube_api.importer import SonarQubeApiImporter
from django.test import TestCase
from dojo.models import Test, Engagement, Product, Sonarqube_Product


def dummy_product(self, *args, **kwargs):
    with open('dojo/unittests/scans/sonarqube_api/product.json') as json_file:
        data = json.load(json_file)
        return data


def dummy_issues(self, *args, **kwargs):
    with open('dojo/unittests/scans/sonarqube_api/issues.json') as json_file:
        data = json.load(json_file)
        return data


def dummy_rule(self, *args, **kwargs):
    with open('dojo/unittests/scans/sonarqube_api/rule.json') as json_file:
        data = json.load(json_file)
        return data


def dummy_no_hotspot(self, *args, **kwargs):
    with open('dojo/unittests/scans/sonarqube_api/hotspots/no_vuln.json') as json_file:
        data = json.load(json_file)
        return data


def dummy_one_hotspot(self, *args, **kwargs):
    with open('dojo/unittests/scans/sonarqube_api/hotspots/one_vuln.json') as json_file:
        data = json.load(json_file)
        return data


def dummy_many_hotspots(self, *args, **kwargs):
    with open('dojo/unittests/scans/sonarqube_api/hotspots/many_vulns.json') as json_file:
        data = json.load(json_file)
        return data


def dummy_hotspot_rule(self, *args, **kwargs):
    with open('dojo/unittests/scans/sonarqube_api/hotspots/rule.json') as json_file:
        data = json.load(json_file)
        return data


def empty_list(self, *args, **kwargs):
    return list()


class TestSonarqubeImporterNoSQToolConfig(TestCase):
    # Testing case no 1. https://github.com/DefectDojo/django-DefectDojo/pull/4676
    fixtures = [
        'unit_sonarqube_toolType.json',
        'unit_sonarqube_product.json'
    ]

    def setUp(self):
        product = Product.objects.get(name='product')
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)

    def test_parser(self):
        with self.assertRaisesRegex(Exception, 'No SonarQube tool is configured.'):
            SonarQubeApiImporter.prepare_client(self.test)


class TestSonarqubeImporterOneSQToolConfig(TestCase):
    # Testing case no 2. https://github.com/DefectDojo/django-DefectDojo/pull/4676
    fixtures = [
        'unit_sonarqube_toolType.json',
        'unit_sonarqube_toolConfig1.json',
        'unit_sonarqube_product.json'
    ]

    def setUp(self):
        product = Product.objects.get(name='product')
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)

    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_project', dummy_product)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_rule', dummy_rule)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_issues', dummy_issues)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_hotspot_rule', dummy_hotspot_rule)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_hotspots', empty_list)
    def test_parser(self):
        parser = SonarQubeApiImporter()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(2, len(findings))


class TestSonarqubeImporterMultipleSQToolConfig(TestCase):
    # Testing case no 3. https://github.com/DefectDojo/django-DefectDojo/pull/4676
    fixtures = [
        'unit_sonarqube_toolType.json',
        'unit_sonarqube_toolConfig1.json',
        'unit_sonarqube_toolConfig2.json',
        'unit_sonarqube_product.json'
    ]

    def setUp(self):
        product = Product.objects.get(name='product')
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)

    def test_parser(self):
        with self.assertRaisesRegex(Exception, 'It has configured more than one SonarQube tool.'):
            SonarQubeApiImporter.prepare_client(self.test)


class TestSonarqubeImporterOneSQConfigNoKey(TestCase):
    # Testing case no 4. https://github.com/DefectDojo/django-DefectDojo/pull/4676 without Project key
    fixtures = [
        'unit_sonarqube_toolType.json',
        'unit_sonarqube_toolConfig1.json',
        'unit_sonarqube_toolConfig2.json',
        'unit_sonarqube_product.json',
        'unit_sonarqube_sqcNoKey.json'
    ]

    def setUp(self):
        product = Product.objects.get(name='product')
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)

    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_project', dummy_product)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_rule', dummy_rule)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_issues', dummy_issues)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_hotspot_rule', dummy_hotspot_rule)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_hotspots', empty_list)
    def test_parser(self):
        parser = SonarQubeApiImporter()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(2, len(findings))


class TestSonarqubeImporterOneSQConfigWithKey(TestCase):
    # Testing case no 5. https://github.com/DefectDojo/django-DefectDojo/pull/4676 without Project key
    fixtures = [
        'unit_sonarqube_toolType.json',
        'unit_sonarqube_toolConfig1.json',
        'unit_sonarqube_toolConfig2.json',
        'unit_sonarqube_product.json',
        'unit_sonarqube_sqcWithKey.json'
    ]

    def setUp(self):
        product = Product.objects.get(name='product')
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)

    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_project', dummy_product)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_rule', dummy_rule)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_issues', dummy_issues)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_hotspot_rule', dummy_hotspot_rule)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_hotspots', empty_list)
    def test_parser(self):
        parser = SonarQubeApiImporter()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(2, len(findings))


class TestSonarqubeImporterMultipleSQConfigs(TestCase):
    # Testing case no 6. https://github.com/DefectDojo/django-DefectDojo/pull/4676 without Project key
    fixtures = [
        'unit_sonarqube_toolType.json',
        'unit_sonarqube_toolConfig1.json',
        'unit_sonarqube_toolConfig2.json',
        'unit_sonarqube_product.json',
        'unit_sonarqube_sqcNoKey.json',
        'unit_sonarqube_sqcWithKey.json'
    ]

    def setUp(self):
        product = Product.objects.get(name='product')
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)

    def test_parser(self):
        with self.assertRaisesRegex(Exception, 'It has configured more than one Product SonarQube Configuration but non of them has been choosen.'):
            SonarQubeApiImporter.prepare_client(self.test)


class TestSonarqubeImporterSelectedSQConfigsNoKey(TestCase):
    # Testing case no 7. https://github.com/DefectDojo/django-DefectDojo/pull/4676 without Project key
    fixtures = [
        'unit_sonarqube_toolType.json',
        'unit_sonarqube_toolConfig1.json',
        'unit_sonarqube_toolConfig2.json',
        'unit_sonarqube_product.json',
        'unit_sonarqube_sqcNoKey.json',
        'unit_sonarqube_sqcWithKey.json'
    ]

    def setUp(self):
        product = Product.objects.get(name='product')
        engagement = Engagement(product=product)
        self.test = Test(
            engagement=engagement,
            sonarqube_config=Sonarqube_Product.objects.all().first()
        )

    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_project', dummy_product)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_rule', dummy_rule)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_issues', dummy_issues)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_hotspot_rule', dummy_hotspot_rule)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_hotspots', empty_list)
    def test_parser(self):
        parser = SonarQubeApiImporter()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(2, len(findings))


class TestSonarqubeImporterSelectedSQConfigsWithKey(TestCase):
    # Testing case no 8. https://github.com/DefectDojo/django-DefectDojo/pull/4676 without Project key
    fixtures = [
        'unit_sonarqube_toolType.json',
        'unit_sonarqube_toolConfig1.json',
        'unit_sonarqube_toolConfig2.json',
        'unit_sonarqube_product.json',
        'unit_sonarqube_sqcNoKey.json',
        'unit_sonarqube_sqcWithKey.json'
    ]

    def setUp(self):
        product = Product.objects.get(name='product')
        engagement = Engagement(product=product)
        self.test = Test(
            engagement=engagement,
            sonarqube_config=Sonarqube_Product.objects.all().last()
        )
        other_product = Product(name='other product')
        other_engagement = Engagement(product=other_product)
        self.other_test = Test(
            engagement=other_engagement,
            sonarqube_config=Sonarqube_Product.objects.all().last()
        )

    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_project', dummy_product)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_rule', dummy_rule)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_issues', dummy_issues)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_hotspot_rule', dummy_hotspot_rule)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_hotspots', empty_list)
    def test_parser(self):
        parser = SonarQubeApiImporter()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(2, len(findings))

    def test_product_mismatch(self):
        with self.assertRaisesRegex(Exception, 'Product SonarQube Configuration and "Product" mismatch'):
            SonarQubeApiImporter.prepare_client(self.other_test)


class TestSonarqubeImporterTwoIssuesNoHotspots(TestCase):
    # Testing case no 9. https://github.com/DefectDojo/django-DefectDojo/pull/4107
    fixtures = [
        'unit_sonarqube_toolType.json',
        'unit_sonarqube_toolConfig1.json',
        'unit_sonarqube_product.json'
    ]

    def setUp(self):
        product = Product.objects.get(name='product')
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)

    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_project', dummy_product)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_rule', dummy_rule)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_issues', dummy_issues)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_hotspot_rule', dummy_hotspot_rule)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_hotspots', empty_list)
    def test_parser(self):
        parser = SonarQubeApiImporter()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(2, len(findings))


class TestSonarqubeImporterNoIssuesOneHotspot(TestCase):
    # Testing case no 10. https://github.com/DefectDojo/django-DefectDojo/pull/4107
    fixtures = [
        'unit_sonarqube_toolType.json',
        'unit_sonarqube_toolConfig1.json',
        'unit_sonarqube_product.json'
    ]

    def setUp(self):
        product = Product.objects.get(name='product')
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)

    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_project', dummy_product)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_rule', dummy_rule)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_issues', empty_list)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_hotspot_rule', dummy_hotspot_rule)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_hotspots', dummy_one_hotspot)
    def test_parser(self):
        parser = SonarQubeApiImporter()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(1, len(findings))


class TestSonarqubeImporterNoIssuesTwoHotspots(TestCase):
    # Testing case no 11. https://github.com/DefectDojo/django-DefectDojo/pull/4107
    fixtures = [
        'unit_sonarqube_toolType.json',
        'unit_sonarqube_toolConfig1.json',
        'unit_sonarqube_product.json'
    ]

    def setUp(self):
        product = Product.objects.get(name='product')
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)

    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_project', dummy_product)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_rule', dummy_rule)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_issues', empty_list)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_hotspot_rule', dummy_hotspot_rule)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_hotspots', dummy_many_hotspots)
    def test_parser(self):
        parser = SonarQubeApiImporter()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(2, len(findings))


class TestSonarqubeImporterTwoIssuesTwoHotspots(TestCase):
    # Testing case no 12. https://github.com/DefectDojo/django-DefectDojo/pull/4107
    fixtures = [
        'unit_sonarqube_toolType.json',
        'unit_sonarqube_toolConfig1.json',
        'unit_sonarqube_product.json'
    ]

    def setUp(self):
        product = Product.objects.get(name='product')
        engagement = Engagement(product=product)
        self.test = Test(engagement=engagement)

    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_project', dummy_product)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_rule', dummy_rule)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_issues', dummy_issues)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.get_hotspot_rule', dummy_hotspot_rule)
    @mock.patch('dojo.tools.sonarqube_api.api_client.SonarQubeAPI.find_hotspots', dummy_many_hotspots)
    def test_parser(self):
        parser = SonarQubeApiImporter()
        findings = parser.get_findings(None, self.test)
        self.assertEqual(4, len(findings))
