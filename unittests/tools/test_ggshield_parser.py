from ..dojo_test_case import DojoTestCase
from dojo.tools.ggshield.parser import GgshieldParser
from dojo.models import Test


class TestGgshieldParser(DojoTestCase):

    def test_parse_empty(self):
        testfile = open("unittests/scans/ggshield/no_finding.json")
        parser = GgshieldParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        testfile = open("unittests/scans/ggshield/one_finding.json")
        parser = GgshieldParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("wapf/settings.py", finding.file_path)
        self.assertEqual("Hard coded Django Secret Key found in wapf/settings.py", finding.title)
        self.assertIsNotNone(finding.description)
        self.assertEqual("2021-07-05", finding.date)

    def test_parse_many_finding(self):
        testfile = open("unittests/scans/ggshield/many_findings.json")
        parser = GgshieldParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(findings))
        finding = findings[0]
        self.assertEqual("wapf/settings.py", finding.file_path)
        self.assertEqual("Hard coded Django Secret Key found in wapf/settings.py", finding.title)
        self.assertIsNotNone(finding.description)
        self.assertEqual("2021-03-13", finding.date)
        finding = findings[1]
        self.assertEqual("wapf/settings.py", finding.file_path)
        self.assertEqual("Hard coded Django Secret Key found in wapf/settings.py", finding.title)
        self.assertIsNotNone(finding.description)
        self.assertEqual("2021-07-05", finding.date)
