from django.test import TestCase

from dojo.models import Finding, Test
from dojo.tools.anchore_grype.parser import AnchoreGrypeParser


class TestAnchoreGrypeParser(TestCase):

    def test_parser_has_no_findings(self):
        testfile = open("dojo/unittests/scans/anchore_grype/no_vuln.json")
        parser = AnchoreGrypeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parser_has_many_findings(self):
        testfile = open("dojo/unittests/scans/anchore_grype/many_vulns.json")
        parser = AnchoreGrypeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(388, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertIsNotNone(finding.cve)
            if finding.unique_id_from_tool == "CVE-2011-3389":
                self.assertEqual("CVE-2011-3389", finding.cve)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual("libgnutls-openssl27", finding.component_name)
                self.assertEqual("3.6.7-4+deb10u5", finding.component_version)

    def test_grype_parser_with_one_criticle_vuln_has_one_findings(self):
        testfile = open("dojo/unittests/scans/anchore_grype/many_vulns2.json")
        parser = AnchoreGrypeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(387, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertIsNotNone(finding.cve)
            if finding.unique_id_from_tool == "CVE-2019-9192":
                self.assertEqual("CVE-2019-9192", finding.cve)
                self.assertEqual("libc6-dev", finding.component_name)
                self.assertEqual("2.28-10", finding.component_version)
                self.assertEqual("Info", finding.severity)

    def test_grype_parser_with_many_vulns3(self):
        testfile = open("dojo/unittests/scans/anchore_grype/many_vulns3.json")
        parser = AnchoreGrypeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(259, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertIsNotNone(finding.cve)
            if finding.unique_id_from_tool == "CVE-2011-3389":
                self.assertEqual("CVE-2011-3389", finding.cve)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual("libgnutls30", finding.component_name)
                self.assertEqual("3.6.7-4+deb10u5", finding.component_version)
