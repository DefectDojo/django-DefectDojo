from django.test import TestCase

from dojo.models import Test, Finding
from dojo.tools.cyclonedx.parser import CycloneDXParser


class TestParser(TestCase):

    def test_grype_report(self):
        with open("dojo/unittests/scans/cyclonedx/grype.xml") as file:
            parser = CycloneDXParser()
            findings = parser.get_findings(file, Test())
            self.assertEqual(327, len(findings))
            for finding in findings:
                self.assertIn(finding.severity, Finding.SEVERITIES)
                if "urn:uuid:06be2823-e8ff-4f98-9d25-3b15155fc7a2" == finding.unique_id_from_tool:
                    with self.subTest(i="urn:uuid:06be2823-e8ff-4f98-9d25-3b15155fc7a2"):
                        finding = findings[0]
                        self.assertEqual("CVE-2011-3374", finding.cve)
                        self.assertEqual("Low", finding.severity)
                        self.assertEqual("apt", finding.component_name)
                        self.assertEqual("1.8.2.1", finding.component_version)

    def test_spec1_report(self):
        with open("dojo/unittests/scans/cyclonedx/spec1.xml") as file:
            parser = CycloneDXParser()
            findings = parser.get_findings(file, Test())
            self.assertEqual(1, len(findings))
            for finding in findings:
                self.assertIn(finding.severity, Finding.SEVERITIES)
                if "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.9" == finding.unique_id_from_tool:
                    with self.subTest(i="pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.9"):
                        finding = findings[0]
                        self.assertEqual("CVE-2018-7489", finding.cve)
                        self.assertEqual("Critical", finding.severity)
                        self.assertIn(finding.cwe, [184, 502])
                        self.assertEqual("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3)
                        self.assertEqual("jackson-databind", finding.component_name)
                        self.assertEqual("2.9.9", finding.component_version)

    def test_cyclonedx_bom_report(self):
        with open("dojo/unittests/scans/cyclonedx/cyclonedx_bom.xml") as file:
            parser = CycloneDXParser()
            findings = parser.get_findings(file, Test())
            self.assertEqual(0, len(findings))
