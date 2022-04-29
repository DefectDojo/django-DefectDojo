import os.path

from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.tools.trivy.parser import TrivyParser
from dojo.models import Test


def sample_path(file_name):
    return os.path.join(get_unit_tests_path() + "/scans/trivy", file_name)


class TestTrivyParser(DojoTestCase):

    def test_legacy_no_vuln(self):
        test_file = open(sample_path("legacy_no_vuln.json"))
        parser = TrivyParser()
        trivy_findings = parser.get_findings(test_file, Test())
        self.assertEqual(len(trivy_findings), 0)

    def test_legacy_many_vulns(self):
        test_file = open(sample_path("legacy_many_vulns.json"))
        parser = TrivyParser()
        findings = parser.get_findings(test_file, Test())
        self.assertEqual(len(findings), 93)
        finding = findings[0]
        self.assertEqual("Low", finding.severity)
        self.assertEqual("CVE-2011-3374", finding.cve)
        self.assertEqual(347, finding.cwe)
        self.assertEqual("apt", finding.component_name)
        self.assertEqual("1.8.2.2", finding.component_version)

    def test_scheme_2_no_vuln(self):
        test_file = open(sample_path("scheme_2_no_vuln.json"))
        parser = TrivyParser()
        trivy_findings = parser.get_findings(test_file, Test())
        self.assertEqual(len(trivy_findings), 0)

    def test_scheme_2_many_vulns(self):
        test_file = open(sample_path("scheme_2_many_vulns.json"))
        parser = TrivyParser()
        findings = parser.get_findings(test_file, Test())

        self.assertEqual(len(findings), 5)

        finding = findings[0]
        self.assertEqual("Medium", finding.severity)
        self.assertEqual('CVE-2020-15999 freetype 2.9.1-r2', finding.title)
        self.assertEqual("CVE-2020-15999", finding.cve)
        self.assertEqual(787, finding.cwe)
        self.assertEqual("freetype", finding.component_name)
        self.assertEqual("2.9.1-r2", finding.component_version)
        self.assertIsNotNone(finding.description)
        self.assertIsNotNone(finding.references)
        self.assertEqual('2.9.1-r3', finding.mitigation)
        self.assertEqual('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H', finding.cvssv3)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        finding = findings[1]
        self.assertEqual("High", finding.severity)
        self.assertEqual('CVE-2020-28196 krb5-libs 1.15.5-r0', finding.title)
        self.assertEqual("CVE-2020-28196", finding.cve)
        self.assertEqual(674, finding.cwe)
        self.assertEqual("krb5-libs", finding.component_name)
        self.assertEqual("1.15.5-r0", finding.component_version)
        self.assertIsNotNone(finding.description)
        self.assertIsNotNone(finding.references)
        self.assertEqual('1.15.5-r1', finding.mitigation)
        self.assertIsNone(finding.cvssv3)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
