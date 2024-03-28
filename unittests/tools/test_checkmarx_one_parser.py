from dojo.models import Test
from dojo.tools.checkmarx_one.parser import CheckmarxOneParser
from ..dojo_test_case import DojoTestCase


class TestCheckmarxOneParser(DojoTestCase):

    def test_checkmarx_one_many_vulns(self):
        with open("unittests/scans/checkmarx_one/checkmarx_one.json") as testfile:
            parser = CheckmarxOneParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(5, len(findings))
            with self.subTest(i=0):
                for finding in findings:
                    self.assertIsNotNone(finding.unique_id_from_tool)
                    self.assertIsNotNone(finding.title)
                    self.assertIsNotNone(finding.test)
                    self.assertIsNotNone(finding.date)
                    self.assertIsNotNone(finding.severity)
                    self.assertIsNotNone(finding.description)
                finding_test = findings[0]
                self.assertEqual("Medium", finding_test.severity)
                self.assertEqual("/src/helpers/Constants.ts", finding_test.file_path)

    def test_checkmarx_one_many_findings(self):
        with open("unittests/scans/checkmarx_one/many_findings.json") as testfile:
            parser = CheckmarxOneParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(6, len(findings))
            with self.subTest(i=0):
                for finding in findings:
                    self.assertIsNotNone(finding.unique_id_from_tool)
                    self.assertIsNotNone(finding.title)
                    self.assertIsNotNone(finding.test)
                    self.assertIsNotNone(finding.date)
                    self.assertIsNotNone(finding.severity)
                    self.assertIsNotNone(finding.description)
                finding_test = findings[0]
                self.assertEqual("High", finding_test.severity)
                self.assertEqual("/qe/testharness/Dockerfile", finding_test.file_path)

    def test_checkmarx_one_no_findings(self):
        with open("unittests/scans/checkmarx_one/no_findings.json") as testfile:
            parser = CheckmarxOneParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))
