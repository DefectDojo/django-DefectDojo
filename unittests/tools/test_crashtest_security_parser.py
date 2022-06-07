from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.tools.crashtest_security.parser import CrashtestSecurityParser
from dojo.models import Test


class TestCrashtestSecurityParser(DojoTestCase):
    def test_crashtest_security_json_parser_empty_file_has_no_findings(self):
        testfile = open("unittests/scans/crashtest_security/empty.json")
        parser = CrashtestSecurityParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_crashtest_security_json_parser_full_file_has_many_findings(self):
        testfile = open("unittests/scans/crashtest_security/full.json")
        parser = CrashtestSecurityParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(73, len(findings))

    def test_crashtest_security_json_parser_extracted_data_file_has_many_findings(self):
        testfile = open(
            get_unit_tests_path() + "/scans/crashtest_security/data_extracted.json"
        )
        parser = CrashtestSecurityParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(73, len(findings))
