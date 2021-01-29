from django.test import TestCase
from dojo.tools.crashtest_security_json.parser import CrashtestSecurityJsonParser
from dojo.models import Test


class TestCrashtestSecurityJsonParser(TestCase):
    def test_crashtest_security_json_parser_empty_file_has_no_findings(self):
        testfile = open("dojo/unittests/scans/crashtest_security_json/empty.json")
        parser = CrashtestSecurityJsonParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_crashtest_security_json_parser_full_file_has_many_findings(self):
        testfile = open("dojo/unittests/scans/crashtest_security_json/full.json")
        parser = CrashtestSecurityJsonParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(73, len(findings))

    def test_crashtest_security_json_parser_extracted_data_file_has_many_findings(self):
        testfile = open(
            "dojo/unittests/scans/crashtest_security_json/data_extracted.json"
        )
        parser = CrashtestSecurityJsonParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(73, len(findings))
