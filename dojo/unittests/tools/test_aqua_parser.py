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

    def test_aqua_parser_for_aqua_severity_critical(self):
        with open("dojo/unittests/scans/aqua/vulns_with_aqua_severity.json") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            nbsev = 0

            for finding in findings:
                if finding.severity == 'Critical':
                    nbsev = nbsev + 1

            self.assertEqual(1, nbsev)

    def test_aqua_parser_for_aqua_severity_high(self):
        with open("dojo/unittests/scans/aqua/vulns_with_aqua_severity.json") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            nbsev = 0

            for finding in findings:
                if finding.severity == 'High':
                    nbsev = nbsev + 1

            self.assertEqual(1, nbsev)

    def test_aqua_parser_for_aqua_severity_medium(self):
        with open("dojo/unittests/scans/aqua/vulns_with_aqua_severity.json") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            nbsev = 0

            for finding in findings:
                if finding.severity == 'Medium':
                    nbsev = nbsev + 1

            self.assertEqual(2, nbsev)

    def test_aqua_parser_for_aqua_severity_low(self):
        with open("dojo/unittests/scans/aqua/vulns_with_aqua_severity.json") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            nbsev = 0

            for finding in findings:
                if finding.severity == 'Low':
                    nbsev = nbsev + 1

            self.assertEqual(2, nbsev)

    def test_aqua_parser_for_aqua_severity_info(self):
        with open("dojo/unittests/scans/aqua/vulns_with_aqua_severity.json") as testfile:
            parser = AquaParser()
            findings = parser.get_findings(testfile, Test())
            nbsev = 0

            for finding in findings:
                if finding.severity == 'Info':
                    nbsev = nbsev + 1

            self.assertEqual(7, nbsev)
