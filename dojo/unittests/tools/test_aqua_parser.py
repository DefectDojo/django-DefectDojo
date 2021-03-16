from django.test import TestCase
from dojo.tools.aqua.parser import AquaParser
from dojo.models import Test


class TestAquaParser(TestCase):
    def test_aqua_parser_has_no_finding(self):
        testfile = open("dojo/unittests/scans/aqua/no_vuln.json")
        parser = AquaParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_aqua_parser_has_one_finding(self):
        testfile = open("dojo/unittests/scans/aqua/one_vuln.json")
        parser = AquaParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))

    def test_aqua_parser_has_many_findings(self):
        testfile = open("dojo/unittests/scans/aqua/many_vulns.json")
        parser = AquaParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(24, len(findings))

    def test_aqua_parser_v2_has_one_finding(self):
        with open("dojo/unittests/scans/aqua/one_v2.json") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_aqua_parser_v2_has_many_findings(self):
        with open("dojo/unittests/scans/aqua/many_v2.json") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))

    def test_aqua_parser_cvssv3_has_no_finding(self):
        with open("dojo/unittests/scans/aqua/many_v2.json") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            nb_cvssv3 = 0
            for finding in findings:
                if finding.cvssv3 is not None:
                    nb_cvssv3 = nb_cvssv3 + 1

            self.assertEqual(0, nb_cvssv3)

    def test_aqua_parser_cvssv3_has_many_findings(self):
        with open("dojo/unittests/scans/aqua/many_vulns.json") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            nb_cvssv3 = 0
            for finding in findings:
                if finding.cvssv3 is not None:
                    nb_cvssv3 = nb_cvssv3 + 1

            self.assertEqual(16, nb_cvssv3)
