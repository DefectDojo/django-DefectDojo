from ..dojo_test_case import DojoTestCase
from dojo.tools.kiuwan_sca.parser import KiuwanSCAParser
from dojo.models import Test

# ./dc-unittest.sh --profile postgres-redis --test-case unittests.tools.test_kiuwan_sca_parser.TestKiuwanSCAParser
class TestKiuwanSCAParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/kiuwan-sca/kiuwan_sca_no_vuln.json")
        parser = KiuwanSCAParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_two_vuln_has_two_findings(self):
        testfile = open("unittests/scans/kiuwan-sca/kiuwan_sca_two_vuln.json")
        parser = KiuwanSCAParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(2, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        testfile = open("unittests/scans/kiuwan-sca/kiuwan_sca_many_vuln.json")
        parser = KiuwanSCAParser()
        findings = parser.get_findings(testfile, Test())
        # also tests deduplication as there are 28 findings in the file:
        self.assertEqual(27, len(findings))

    def test_correct_mapping(self):
        testfile = open("unittests/scans/kiuwan-sca/kiuwan_sca_two_vuln.json")
        parser = KiuwanSCAParser()
        findings = parser.get_findings(testfile, Test())
        print(findings)
        finding1 = findings[0]
        self.assertEqual(finding1.title, "Kiuwan Insights finding: CVE-2021-30468")
        self.assertEqual(finding1.severity, "High")
        self.assertEqual(finding1.component_name, "org.apache.cxf:cxf-rt-ws-policy")
        self.assertEqual(finding1.component_version, "3.3.5")
        self.assertEqual(finding1.cve, "CVE-2021-30468")
        self.assertEqual(finding1.cwe, 835)
