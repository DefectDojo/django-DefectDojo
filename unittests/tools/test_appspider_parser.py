
from dojo.models import Engagement, Finding, Product, Test
from dojo.tools.appspider.parser import AppSpiderParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestAppSpiderParser(DojoTestCase):
    def test_appspider_parser_has_one_finding(self):
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        testfile = (get_unit_tests_scans_path("appspider") / "one_vuln.xml").open(encoding="utf-8")
        parser = AppSpiderParser()
        findings = parser.get_findings(testfile, test)
        self.validate_locations(findings)
        testfile.close()
        self.assertEqual(1, len(findings))
        item = findings[0]
        with self.subTest(item=0):
            self.assertEqual(525, item.cwe)

    def convert_severity(self):
        with self.subTest(val="0-Safe"):
            self.assertIn(Finding.SEVERITIES, AppSpiderParser.convert_severity("0-Safe"))

    def test_appspider_parser_duplicate_vulns(self):
        """Verify duplicate findings merge without AttributeError on unsaved_req_resp."""
        test = Test()
        test.engagement = Engagement()
        test.engagement.product = Product()
        with (get_unit_tests_scans_path("appspider") / "duplicate_vulns.xml").open(encoding="utf-8") as testfile:
            parser = AppSpiderParser()
            findings = parser.get_findings(testfile, test)
            self.validate_locations(findings)
            # Both vulns share severity+title key, so they merge into 1
            self.assertEqual(1, len(findings))
            # The merged finding should have 2 req/resp pairs
            self.assertEqual(2, len(findings[0].unsaved_req_resp))
