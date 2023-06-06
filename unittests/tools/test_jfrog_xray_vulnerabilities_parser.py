from ..dojo_test_case import DojoTestCase
from dojo.models import Test, Finding
from dojo.tools.jfrog_xray_vulnerabilities.parser import \
    JFrogXrayVulnerabilitiesParser, decode_cwe_number


class TestJfrogJFrogXrayVulnerabilitiesParser(DojoTestCase):

    def test_parse_file_with_one_vuln(self):
        testfile = open("unittests/scans/jfrog_xray_vulnerabilities/one_vuln.json")
        parser = JFrogXrayVulnerabilitiesParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        item: Finding = findings[0]
        self.assertEqual("gav://org.yaml:snakeyaml:1.16", item.component_name)
        self.assertEqual("CVE-2017-18640", item.unsaved_vulnerability_ids[0])
        self.assertEqual("High", item.severity)

    def test_parse_file_with_many_vulns(self):
        testfile = open("unittests/scans/jfrog_xray_vulnerabilities/many_vulns.json")
        parser = JFrogXrayVulnerabilitiesParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(3, len(findings))

    def test_decode_cwe_number(self):
        with self.subTest(val="CWE-1234"):
            self.assertEqual(1234, decode_cwe_number("CWE-1234"))
        with self.subTest(val=""):
            self.assertEqual(0, decode_cwe_number(""))
        with self.subTest(val="cwe-1"):
            self.assertEqual(1, decode_cwe_number("cwe-1"))
