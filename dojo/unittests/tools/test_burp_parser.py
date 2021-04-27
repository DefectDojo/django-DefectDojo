import os.path

from django.test import TestCase
from dojo.tools.burp.parser import BurpParser
from dojo.models import Test


def sample_path(file_name):
    return os.path.join("dojo/unittests/scans/burp", file_name)


class TestBurpParser(TestCase):

    def test_burp_with_one_vuln_has_one_finding(self):
        with open(sample_path("one_finding.xml")) as test_file:
            parser = BurpParser()
            findings = parser.get_findings(test_file, Test())

            self.assertEqual(1, len(findings))
            self.assertEqual("1049088", findings[0].vuln_id_from_tool)
            self.assertEqual(3, len(findings[0].unsaved_endpoints))

    def test_burp_with_multiple_vulns_has_multiple_findings(self):
        with open(sample_path("seven_findings.xml")) as test_file:
            parser = BurpParser()
            findings = parser.get_findings(test_file, Test())

            self.assertEqual(7, len(findings))

    def test_burp_with_one_vuln_with_blank_response(self):
        with open(sample_path("one_finding_with_blank_response.xml")) as test_file:
            parser = BurpParser()
            findings = parser.get_findings(test_file, Test())

            self.assertEqual(1, len(findings))

            self.assertEqual("7121655797013284864", findings[0].unique_id_from_tool)
            self.assertEqual("1049088", findings[0].vuln_id_from_tool)
            self.assertEqual("SQL injection", findings[0].title)
            self.assertEqual(1, len(findings[0].unsaved_endpoints))

    def test_burp_with_one_vuln_with_cwe(self):
        with open(sample_path("one_finding_with_cwe.xml")) as test_file:
            parser = BurpParser()
            findings = parser.get_findings(test_file, Test())

            self.assertEqual(1, len(findings))

            self.assertEqual("456437653765735", findings[0].unique_id_from_tool)
            self.assertEqual("7340288", findings[0].vuln_id_from_tool)
            self.assertEqual("Cacheable HTTPS response", findings[0].title)
            self.assertEqual(524, findings[0].cwe)
