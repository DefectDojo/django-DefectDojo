from dojo.models import Test
from dojo.tools.redhatsatellite.parser import RedHatSatelliteParser
from unittests.dojo_test_case import DojoTestCase


class TestRedHatSatelliteParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        with open("unittests/scans/redhatsatellite/no_findings.json", encoding="utf-8") as testfile:
            parser = RedHatSatelliteParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_file_with_one_finding(self):
        with open("unittests/scans/redhatsatellite/one_finding.json", encoding="utf-8") as testfile:
            parser = RedHatSatelliteParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_findingse(self):
        with open("unittests/scans/redhatsatellite/many_findings.json", encoding="utf-8") as testfile:
            parser = RedHatSatelliteParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(3, len(findings))
            self.assertEqual("RHSA-1966:12313", findings[0].unsaved_vulnerability_ids[0])
            self.assertEqual("CVE-1990-1", findings[0].unsaved_vulnerability_ids[1])
            self.assertEqual("CVE-1990-2", findings[0].unsaved_vulnerability_ids[2])

    def test_parse_file_with_many_packages(self):
        with open("unittests/scans/redhatsatellite/many_packages.json", encoding="utf-8") as testfile:
            parser = RedHatSatelliteParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            self.assertEqual("RHBA-1999:5678", findings[0].unsaved_vulnerability_ids[0])
