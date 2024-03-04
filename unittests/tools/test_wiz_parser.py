
from ..dojo_test_case import DojoTestCase
from dojo.models import Test
from dojo.tools.wiz.parser import WizParser


class TestWizParser(DojoTestCase):
    def test_multiple_findings(self):
        with self.assertRaises(ValueError):
            testfile = open("unittests/scans/wiz/multiple_findings.csv")
            parser = WizParser()
            parser.get_findings(testfile, Test())
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

    def test_multiple_oscf_findings(self):
        with self.assertRaises(ValueError):
            testfile = open("unittests/scans/wiz/multiple_oscf_findings.csv")
            parser = WizParser()
            parser.get_findings(testfile, Test())
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
