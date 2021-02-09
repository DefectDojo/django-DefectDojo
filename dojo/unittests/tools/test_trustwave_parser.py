import os.path

from django.test import TestCase
from dojo.tools.trustwave.parser import TrustwaveParser
from dojo.models import Test, Engagement, Product


def sample_path(file_name):
    return os.path.join("dojo/unittests/scans/trustwave", file_name)


class TestTrivyParser(TestCase):

    def test_no_vuln(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        test_file = open(sample_path("many_vulns.csv"))
        parser = TrustwaveParser()
        findings = parser.get_findings(test_file, test)
        self.assertEqual(len(findings), 4)
        finding = findings[0]
        self.assertEqual("High", finding.severity)
        self.assertEqual("CVE-3011-123", finding.cve)
        finding = findings[1]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("CVE-3011-321", finding.cve)
        finding = findings[2]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("CVE-3011-313", finding.cve)
        finding = findings[3]
        self.assertEqual("Critical", finding.severity)
        self.assertEqual("CVE-3011-32", finding.cve)
