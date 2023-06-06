from django.test import TestCase
from dojo.tools.whispers.parser import WhispersParser
from dojo.models import Test


class TestWhispersParser(TestCase):

    def test_whispers_parser_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/whispers/whispers_zero_vul.json")
        parser = WhispersParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_whispers_parser_with_one_critical_vuln_has_one_findings(self):
        testfile = open("unittests/scans/whispers/whispers_one_vul.json")
        parser = WhispersParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(1, len(findings))
        self.assertEqual("src/pip.conf", findings[0].file_path)
        self.assertEqual(2, findings[0].line)
        self.assertEqual("pip.conf Password", findings[0].vuln_id_from_tool)

    def test_whispers_parser_with_many_vuln_has_many_findings(self):
        testfile = open("unittests/scans/whispers/whispers_many_vul.json")
        parser = WhispersParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        for finding in findings:
            for endpoint in finding.unsaved_endpoints:
                endpoint.clean()
        self.assertEqual(5, len(findings))
