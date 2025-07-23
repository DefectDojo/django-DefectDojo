from dojo.models import Test
from dojo.tools.xeol.parser import XeolParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestXeolParser(DojoTestCase):

    def test_parse_file_with_one_finding(self):
        testfile = (get_unit_tests_scans_path("xeol") / "one_vuln.json").open(encoding="utf-8")
        parser = XeolParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        finding = list(findings)[0]
        self.assertEqual(finding.severity, "Info")
