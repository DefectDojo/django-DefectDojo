
from dojo.models import Test
from dojo.tools.blackduck_binary_analysis.parser import BlackduckBinaryAnalysisParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestBlackduckBinaryAnalysisParser(DojoTestCase):
    def test_parse_no_vulns(self):
        with (get_unit_tests_scans_path("blackduck_binary_analysis") / "no_vuln.csv").open(encoding="utf-8") as testfile:
            parser = BlackduckBinaryAnalysisParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_vuln(self):
        with (get_unit_tests_scans_path("blackduck_binary_analysis") / "one_vuln.csv").open(encoding="utf-8") as testfile:
            parser = BlackduckBinaryAnalysisParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            for finding in findings:
                self.assertIsNotNone(finding.title)
                self.assertEqual(
                    "instrument.dll: zlib 1.2.13 Vulnerable to CVE-2023-45853",
                    finding.title,
                )
                self.assertEqual(True, finding.fix_available)
                self.assertIsNotNone(finding.description)
                self.assertIsNotNone(finding.severity)
                self.assertEqual("Critical", finding.severity)
                self.assertIsNotNone(finding.component_name)
                self.assertEqual("zlib", finding.component_name)
                self.assertIsNotNone(finding.component_version)
                self.assertEqual("1.2.13", finding.component_version)
                self.assertIsNotNone(finding.file_path)
                self.assertEqual(
                    "JRE.msi:JRE.msi-30276-90876123.cab:instrument.dll",
                    finding.file_path,
                )
                self.assertIsNotNone(finding.vuln_id_from_tool)
                self.assertEqual("CVE-2023-45853", finding.vuln_id_from_tool)
                self.assertIsNotNone(finding.unique_id_from_tool)
                # Verify vulnerability_id is populated for de-duplication
                self.assertIsNotNone(finding.unsaved_vulnerability_ids)
                self.assertEqual(["CVE-2023-45853"], finding.unsaved_vulnerability_ids)

    def test_parse_many_vulns(self):
        with (get_unit_tests_scans_path("blackduck_binary_analysis") / "many_vulns.csv").open(encoding="utf-8") as testfile:
            parser = BlackduckBinaryAnalysisParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(5, len(findings))
            for finding in findings:
                self.assertIsNotNone(finding.title)
                self.assertIsNotNone(finding.description)
                self.assertIsNotNone(finding.severity)
                self.assertIsNotNone(finding.component_name)
                self.assertIsNotNone(finding.component_version)
                self.assertIsNotNone(finding.file_path)
                self.assertIsNotNone(finding.vuln_id_from_tool)
                self.assertIsNotNone(finding.unique_id_from_tool)
                # Verify vulnerability_id is populated for de-duplication
                self.assertIsNotNone(finding.unsaved_vulnerability_ids)
                self.assertGreater(len(finding.unsaved_vulnerability_ids), 0)
