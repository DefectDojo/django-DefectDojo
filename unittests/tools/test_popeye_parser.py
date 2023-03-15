from ..dojo_test_case import DojoTestCase
from dojo.tools.popeye.parser import PopeyeParser
from dojo.models import Test


class TestPopeyeParser(DojoTestCase):

    def test_popeye_parser_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/popeye/popeye_zero_vul.json")
        parser = PopeyeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_popeye_parser_with_one_warning_has_one_findings(self):
        testfile = open("unittests/scans/popeye/popeye_one_vul.json")
        parser = PopeyeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))
        self.assertEqual("Low", findings[0].severity)

    def test_popeye_parser_with_many_vuln_has_many_findings(self):
        testfile = open("unittests/scans/popeye/popeye_many_vul.json")
        parser = PopeyeParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(229, len(findings))
