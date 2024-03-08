from dojo.models import Test
from dojo.tools.checkmarx_one.parser import CheckmarxOneParser
from ..dojo_test_case import DojoTestCase


class TestCheckmarxOneParser(DojoTestCase):

    def test_checkmarx_one_many_vulns(self):
        with open("unittests/scans/checkmarx_one/checkmarx_one.json") as testfile:
            parser = CheckmarxOneParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            self.assertEqual(99, len(findings))
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
                self.assertEqual("/src/helpers/ConstantsHelper.ts", finding_test.file_path)

    def test_checkmarx_one_checkmarx_apigateway(self):
        with open("unittests/scans/checkmarx_one/checkmarx_apigateway.json") as testfile:
            parser = CheckmarxOneParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(156, len(findings))
            with self.subTest(i=0):
                for finding in findings:
                    self.assertIsNotNone(finding.unique_id_from_tool)
                    self.assertIsNotNone(finding.title)
                    self.assertIsNotNone(finding.test)
                    self.assertIsNotNone(finding.date)
                    self.assertIsNotNone(finding.severity)
                    self.assertIsNotNone(finding.description)
                finding_test = findings[0]
                self.assertEqual("Low", finding_test.severity)
                self.assertEqual("/docker-compose.yml", finding_test.file_path)

    def test_checkmarx_one_checkmarx_gibraltar(self):
        with open("unittests/scans/checkmarx_one/checkmarx_gibraltar.json") as testfile:
            parser = CheckmarxOneParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1205, len(findings))
            with self.subTest(i=0):
                for finding in findings:
                    self.assertIsNotNone(finding.unique_id_from_tool)
                    self.assertIsNotNone(finding.title)
                    self.assertIsNotNone(finding.test)
                    self.assertIsNotNone(finding.date)
                    self.assertIsNotNone(finding.severity)
                    self.assertIsNotNone(finding.description)
                finding_test = findings[0]
                self.assertEqual("Info", finding_test.severity)
                self.assertEqual("/services/health-care-provider-api/src/providers/__test__/salesforce-connection.provider.test.ts", finding_test.file_path)
