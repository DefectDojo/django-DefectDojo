from django.test import TestCase
from dojo.models import Test
from dojo.tools.qualys.parser import QualysParser


class TestQualysParser(TestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open(
            "dojo/unittests/scans/qualys/empty.xml"
        )
        parser = QualysParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        testfile = open(
            "dojo/unittests/scans/qualys/Qualys_Sample_Report.xml"
        )
        parser = QualysParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(299, len(findings))

        finding = findings[0]
        self.assertEqual(
            finding.title, "QID-6 | DNS Host Name"
        )
        self.assertEqual(
            finding.severity, "Informational"
        )
        self.assertEqual(
            finding.unsaved_endpoints[0].host, "demo13.s02.sjc01.qualys.com"
        )
