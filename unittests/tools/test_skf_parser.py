from ..dojo_test_case import DojoTestCase
from dojo.tools.skf.parser import SKFParser
from dojo.models import Test


class TestSkfParser(DojoTestCase):

    def test_single_has_no_finding(self):
        testfile = open("unittests/scans/skf/export.csv")
        parser = SKFParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(27, len(findings))
        # finding 0
        finding = findings[0]
        self.assertEqual("Authentication Verification Requirements : Verify that user set passwords are at least 12 characters in length. (C6)", finding.title)
        self.assertEqual("Info", finding.severity)
