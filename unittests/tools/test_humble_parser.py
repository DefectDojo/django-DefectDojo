from dojo.tools.humble.parser import HumbleParser
from dojo.models import Test
from unittests.dojo_test_case import DojoTestCase


class TestHumbleParser(DojoTestCase):
    def test_humble_parser_with_many_findings(self):
        testfile = open("unittests/scans/humble/many_findings.json")
        parser = HumbleParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(9, len(findings))
        finding = findings[0]
        self.assertEqual("https://asdf.asf.hs_missing_Clear-Site-Data", finding.title)
        finding = findings[7]
        self.assertEqual("https://asdf.asf.hs_deprecatedheader_Strict-Transport-Security (Recommended Values)", finding.title)
