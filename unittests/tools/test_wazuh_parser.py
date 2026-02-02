from dojo.models import Test
from dojo.tools.wazuh.parser import WazuhParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestWazuhParser(DojoTestCase):

    def test_parse_v4_7_no_findings(self):
        with (get_unit_tests_scans_path("wazuh") / "v4-7_no_findings.json").open(encoding="utf-8") as testfile:
            parser = WazuhParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_v4_7_one_finding(self):
        with (get_unit_tests_scans_path("wazuh") / "v4-7_one_finding.json").open(encoding="utf-8") as testfile:
            parser = WazuhParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            self.validate_locations(findings)
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("CVE-1234-123123", finding.unsaved_vulnerability_ids)
            self.assertEqual("asdf", finding.component_name)
            self.assertEqual("4.3.1", finding.component_version)
            self.assertEqual(5.5, finding.cvssv3_score)

    def test_parse_v4_7_many_finding(self):
        with (get_unit_tests_scans_path("wazuh") / "v4-7_many_findings.json").open(encoding="utf-8") as testfile:
            parser = WazuhParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(6, len(findings))
            self.validate_locations(findings)
            finding = findings[-1]
            self.assertEqual("2023-02-08", finding.date)

    def test_parse_v4_7_one_finding_with_location(self):
        with (get_unit_tests_scans_path("wazuh") / "v4-7_one_finding_with_endpoint.json").open(encoding="utf-8") as testfile:
            parser = WazuhParser()
            findings = parser.get_findings(testfile, Test())
            self.validate_locations(findings)
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("CVE-1234-1234", finding.unsaved_vulnerability_ids)
            self.assertEqual(6.5, finding.cvssv3_score)
            location = self.get_unsaved_locations(finding)[0]
            self.assertEqual("agent-1", location.host)
            self.assertEqual("asdf", finding.component_name)
            self.assertEqual("1", finding.component_version)
            self.assertEqual("2023-12-13", finding.date)

    def test_parse_v4_8_many_findings(self):
        with (get_unit_tests_scans_path("wazuh") / "v4-8_many_findings.json").open(encoding="utf-8") as testfile:
            parser = WazuhParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(10, len(findings))
            self.validate_locations(findings)
            self.assertEqual("CVE-2025-27558 affects (version: 6.8.0-60.63)", findings[0].title)
            self.assertEqual("Critical", findings[0].severity)
            self.assertEqual(9.1, findings[0].cvssv3_score)

    def test_parse_wazuh_abnormal_severity(self):
        with (get_unit_tests_scans_path("wazuh") / "wazuh_abnormal_severity.json").open(encoding="utf-8") as testfile:
            parser = WazuhParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                self.assertEqual("Info", finding.severity)
