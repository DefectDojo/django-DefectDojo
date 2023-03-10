from django.test import TestCase
from dojo.tools.popeye.parser import PopeyeParserParser
from dojo.models import Test


class TestPopeyeParserParser(TestCase):

    def test_popeye_parser_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/popeye/popeye_zero_vul.json")
        parser = PopeyeParserParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_popeye_parser_with_one_criticle_vuln_has_one_findings(self):
        testfile = open("unittests/scans/popeye/popeye_one_vul.json")
        parser = PopeyeParserParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        self.assertEqual("handlebars", findings[0].component_name)
        self.assertEqual("4.5.2", findings[0].component_version)

    def test_popeye_parser_with_many_vuln_has_many_findings(self):
        testfile = open("unittests/scans/popeye/popeye_many_vul.json")
        parser = PopeyeParserParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(3, len(findings))

    def test_popeye_parser_empty_with_error(self):
        with self.assertRaises(ValueError) as context:
            testfile = open("unittests/scans/popeye/empty_with_error.json")
            parser = PopeyeParserParser()
            findings = parser.get_findings(testfile, Test())
            testfile.close()
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertTrue(
                "popeye report contains errors:" in str(context.exception)
            )
            self.assertTrue("ECONNREFUSED" in str(context.exception))
