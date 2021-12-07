from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.models import Test
from dojo.tools.qualys.parser import QualysParser


class TestQualysParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open(
            get_unit_tests_path() + "/scans/qualys/empty.xml"
        )
        parser = QualysParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_findings(self):
        testfile = open(
            get_unit_tests_path() + "/scans/qualys/Qualys_Sample_Report.xml"
        )
        parser = QualysParser()
        findings = parser.get_findings(testfile, Test())
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(301, len(findings))

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
        for finding in findings:
            if finding.unsaved_endpoints[0].host == "demo14.s02.sjc01.qualys.com" and finding.title == "QID-370876 | AMD Processors Multiple Security Vulnerabilities (RYZENFALL/MASTERKEY/CHIMERA-FW/FALLOUT)":
                finding_cvssv3_score = finding
            if finding.unsaved_endpoints[0].host == "demo13.s02.sjc01.qualys.com" and finding.title == "QID-370876 | AMD Processors Multiple Security Vulnerabilities (RYZENFALL/MASTERKEY/CHIMERA-FW/FALLOUT)":
                finding_cvssv3_vector = finding
        self.assertEqual(
            # CVSS_FINAL is defined without a cvssv3 vector
            finding_cvssv3_score.cvssv3, None
        )
        self.assertEqual(
            finding_cvssv3_score.severity, "High"
        )
        self.assertEqual(
            finding_cvssv3_vector.cvssv3, "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"
        )
        self.assertEqual(
            finding_cvssv3_vector.severity, "Critical"
        )
