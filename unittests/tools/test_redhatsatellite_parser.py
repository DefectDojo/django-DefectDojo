from ..dojo_test_case import DojoTestCase
from dojo.tools.redhatsatellite.parser import RedHatSatelliteParser
from dojo.models import Test


class TestRedHatSatelliteParser(DojoTestCase):

    def test_parse_file_with_no_vuln_has_no_findings(self):
        testfile = open("unittests/scans/redhatsatellite/no_findings.json")
        parser = RedHatSatelliteParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_parse_file_with_one_finding(self):
        testfile = open("unittests/scans/redhatsatellite/one_finding.json")
        parser = RedHatSatelliteParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_multiple_findingse(self):
        testfile = open("unittests/scans/redhatsatellite/many_findings.json")
        parser = RedHatSatelliteParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(3, len(findings))
        self.assertEqual("RHSA-1966:12313", findings[0].unsaved_vulnerability_ids[0])
        self.assertEqual("CVE-1990-1", findings[0].unsaved_vulnerability_ids[1])
        self.assertEqual("CVE-1990-2", findings[0].unsaved_vulnerability_ids[2])
