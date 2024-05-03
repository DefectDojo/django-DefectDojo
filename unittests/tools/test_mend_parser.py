from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.tools.mend.parser import MendParser
from dojo.models import Test


class TestMendParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/mend/okhttp_no_vuln.json")
        parser = MendParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        testfile = open("unittests/scans/mend/okhttp_one_vuln.json")
        parser = MendParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        finding = list(findings)[0]
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2019-9658", finding.unsaved_vulnerability_ids[0])
        self.assertEqual("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", finding.cvssv3)
        self.assertEqual(5.3, finding.cvssv3_score)

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        testfile = open("unittests/scans/mend/okhttp_many_vuln.json")
        parser = MendParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(6, len(findings))

    def test_parse_file_with_multiple_vuln_cli_output(self):
        testfile = open(
            get_unit_tests_path() + "/scans/mend/cli_generated_many_vulns.json"
        )
        parser = MendParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(20, len(findings))
