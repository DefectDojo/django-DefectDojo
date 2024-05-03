from dojo.models import Test
from dojo.tools.progpilot.parser import ProgpilotParser

from ..dojo_test_case import DojoTestCase


class TestProgpilotParser(DojoTestCase):

    def test_progpilotparser_single_has_many_findings(self):
        testfile = open("unittests/scans/progpilot/progpilot.json")
        parser = ProgpilotParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(findings))
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertIsNotNone(finding.description)
            self.assertGreater(len(finding.description), 0)
            self.assertEqual(89, finding.cwe)
            self.assertEqual("sql_injection", finding.title)
            self.assertEqual("/home/User/Modules/progpilot/Order.php", finding.file_path)
            self.assertEqual(593, finding.line)

    def test_progpilotparser_single_has_one_finding(self):
        testfile = open("unittests/scans/progpilot/progpilot2.json")
        parser = ProgpilotParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))

    def test_progpilotparser_single_has_many_findings3(self):
        testfile = open("unittests/scans/progpilot/progpilot3.json")
        parser = ProgpilotParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(3, len(findings))

    def test_progpilotparser_single_has_many_findings4(self):
        testfile = open("unittests/scans/progpilot/progpilot4.json")
        parser = ProgpilotParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(2, len(findings))
