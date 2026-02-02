
from dojo.models import Test
from dojo.tools.openscap.parser import OpenscapParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestOpenscapParser(DojoTestCase):

    def test_openscap_parser_with_no_vuln_has_no_findings(self):
        testfile = (get_unit_tests_scans_path("openscap") / "no_vuln_rhsa.xml").open(encoding="utf-8")
        parser = OpenscapParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_openscap_parser_with_one_criticle_vuln_has_one_findings(self):
        testfile = (get_unit_tests_scans_path("openscap") / "one_vuln_rhsa.xml").open(encoding="utf-8")
        parser = OpenscapParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.validate_locations(findings)
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2005-1038", finding.unsaved_vulnerability_ids[0])

    def test_openscap_parser_with_many_vuln_has_many_findings(self):
        testfile = (get_unit_tests_scans_path("openscap") / "many_vuln_rhsa.xml").open(encoding="utf-8")
        parser = OpenscapParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.validate_locations(findings)
        self.assertEqual(31, len(findings))
        finding = findings[0]
        self.assertEqual("RHSA-2017:3315: kernel security and bug fix update (Moderate)", finding.title)
        self.assertEqual("Medium", finding.severity)
        self.assertEqual(1, len(finding.unsaved_vulnerability_ids))
        self.assertEqual("CVE-2017-1000380", finding.unsaved_vulnerability_ids[0])
        self.assertEqual("oval-com.redhat.rhsa-def-20173315", finding.unique_id_from_tool)
        # locations
        self.assertEqual(7, len(self.get_unsaved_locations(finding)))
        self.assertEqual("sample.system", self.get_unsaved_locations(finding)[0].host)
        self.assertEqual("127.0.0.1", self.get_unsaved_locations(finding)[1].host)
        self.assertEqual("192.168.94.166", self.get_unsaved_locations(finding)[2].host)
        self.assertEqual("192.168.94.53", self.get_unsaved_locations(finding)[3].host)
        self.assertEqual("192.168.83.194", self.get_unsaved_locations(finding)[4].host)
        self.assertEqual("192.168.85.194", self.get_unsaved_locations(finding)[5].host)
        self.assertEqual("192.168.100.194", self.get_unsaved_locations(finding)[6].host)

    def test_parser_from_spec_1_1_3(self):
        testfile = (get_unit_tests_scans_path("openscap") / "ios-sample-v1.1.3.xccdf.xml").open(encoding="utf-8")
        parser = OpenscapParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.validate_locations(findings)
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("IOS 12 - no IP finger service", finding.title)
        self.assertEqual("Medium", finding.severity)
        self.assertIsNone(finding.unsaved_vulnerability_ids)
        self.assertEqual("ios12-no-finger-service", finding.unique_id_from_tool)
        # locations
        self.assertEqual(3, len(self.get_unsaved_locations(finding)))
        self.assertEqual("lower.test.net", self.get_unsaved_locations(finding)[0].host)
        self.assertEqual("192.168.248.1", self.get_unsaved_locations(finding)[1].host)
        self.assertEqual("2001:8::1", self.get_unsaved_locations(finding)[2].host)
