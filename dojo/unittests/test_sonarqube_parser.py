from django.test import TestCase

from dojo.models import Test, Engagement, Product
from dojo.tools.sonarqube.parser import SonarQubeHtmlParser


class TestSonarQubeParser(TestCase):

    def test_parse_file_with_no_vulnerabilities_has_no_findings(self):
        my_file_handle = open("dojo/unittests/scans/sonarqube/sonar-no-finding.html")
        product = Product()
        engagement = Engagement()
        test = Test()
        engagement.product = product
        test.engagement = engagement
        self.parser = SonarQubeHtmlParser(my_file_handle, test)
        my_file_handle.close()
        self.assertEqual(0, len(self.parser.items))

    def test_parse_file_with_single_vulnerability_has_single_finding(self):
        my_file_handle = open("dojo/unittests/scans/sonarqube/sonar-single-finding.html")
        product = Product()
        engagement = Engagement()
        test = Test()
        engagement.product = product
        test.engagement = engagement
        self.parser = SonarQubeHtmlParser(my_file_handle, test)
        my_file_handle.close()
        self.assertEqual(1, len(self.parser.items))

    def test_parse_file_with_multiple_vulnerabilities_has_multiple_findings(self):
        my_file_handle = open("dojo/unittests/scans/sonarqube/sonar-6-findings.html")
        product = Product()
        engagement = Engagement()
        test = Test()
        engagement.product = product
        test.engagement = engagement
        self.parser = SonarQubeHtmlParser(my_file_handle, test)
        my_file_handle.close()
        self.assertEqual(6, len(self.parser.items))
