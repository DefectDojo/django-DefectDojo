from ..dojo_test_case import DojoTestCase
from dojo.tools.cobalt.parser import CobaltParser
from dojo.models import Test


class TestCobaltParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):

        with open("unittests/scans/cobalt/cobalt_no_vuln.csv") as testfile:
            parser = CobaltParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_vuln_has_one_findings(self):
        with open("unittests/scans/cobalt/cobalt_one_vuln.csv") as testfile:
            parser = CobaltParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_vuln_has_multiple_finding(self):
        with open("unittests/scans/cobalt/cobalt_many_vuln.csv") as testfile:
            parser = CobaltParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(9, len(findings))
