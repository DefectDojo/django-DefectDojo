from ..dojo_test_case import DojoTestCase
from dojo.models import Test
from dojo.tools.progpilot.parser import ProgpilotParser


class TestProgpilotParser(DojoTestCase):

    def test_crunch42parser_single_has_many_findings(self):
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
            self.assertEqual("/home/User/Modules/progpilot/Order.php",finding.file_path)
            self.assertEqual(593,finding.line)
