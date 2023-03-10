from ..dojo_test_case import DojoTestCase, get_unit_tests_path
from dojo.tools.dependency_track.parser import DependencyTrackParser
from dojo.models import Test


class TestDependencyTrackParser(DojoTestCase):

    def test_dependency_track_parser_with_empty_list_for_findings_key_has_no_findings(
        self,
    ):
        testfile = open(
            get_unit_tests_path() + "/scans/dependency_track/no_findings_because_findings_key_is_empty_list.json"
        )
        parser = DependencyTrackParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_dependency_track_parser_with_missing_findings_key_has_no_findings(self):
        testfile = open(
            get_unit_tests_path() + "/scans/dependency_track/no_findings_because_findings_key_is_missing.json"
        )
        parser = DependencyTrackParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_dependency_track_parser_with_null_findings_key_has_no_findings(self):
        testfile = open(
            get_unit_tests_path() + "/scans/dependency_track/no_findings_because_findings_key_is_null.json"
        )
        parser = DependencyTrackParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(0, len(findings))

    def test_dependency_track_parser_has_many_findings(self):
        testfile = open(
            get_unit_tests_path() + "/scans/dependency_track/many_findings.json"
        )
        parser = DependencyTrackParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(4, len(findings))

        self.assertIsNone(findings[0].unsaved_vulnerability_ids)
        self.assertIsNone(findings[1].unsaved_vulnerability_ids)
        self.assertEqual(1, len(findings[2].unsaved_vulnerability_ids))
        self.assertEqual('CVE-2016-2097', findings[2].unsaved_vulnerability_ids[0])
        self.assertEqual(1, len(findings[3].unsaved_vulnerability_ids))
        self.assertEqual('CVE-2016-2097', findings[3].unsaved_vulnerability_ids[0])

    def test_dependency_track_parser_has_one_finding(self):
        testfile = open(
            get_unit_tests_path() + "/scans/dependency_track/one_finding.json"
        )
        parser = DependencyTrackParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(1, len(findings))

    def test_dependency_track_parser_v3_8_0(self):
        testfile = open(
            get_unit_tests_path() + "/scans/dependency_track/dependency_track_3.8.0_2021-01-18.json"
        )
        parser = DependencyTrackParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()
        self.assertEqual(9, len(findings))
        self.assertTrue(all(item.file_path is not None for item in findings))
        self.assertTrue(all(item.vuln_id_from_tool is not None for item in findings))

    def test_dependency_track_parser_findings_with_alias(self):
        testfile = open(
            get_unit_tests_path() + "/scans/dependency_track/many_findings_with_alias.json"
        )
        parser = DependencyTrackParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        self.assertEqual(12, len(findings))
        self.assertTrue(all(item.file_path is not None for item in findings))
        self.assertTrue(all(item.vuln_id_from_tool is not None for item in findings))
        self.assertTrue('CVE-2022-42004' in findings[0].unsaved_vulnerability_ids)

    def test_dependency_track_parser_findings_with_empty_alias(self):
        testfile = open(
            get_unit_tests_path() + "/scans/dependency_track/many_findings_with_empty_alias.json"
        )
        parser = DependencyTrackParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        self.assertEqual(12, len(findings))
        self.assertTrue('CVE-2022-2053' in findings[11].unsaved_vulnerability_ids)

    def test_dependency_track_parser_findings_with_state(self):
        testfile = open(
            get_unit_tests_path() + "/scans/dependency_track/with_state_fp_na_resolved"
        )
        parser = DependencyTrackParser()
        findings = parser.get_findings(testfile, Test())
        testfile.close()

        self.assertTrue(findings[0].false_p and findings[0].is_mitigated)
        self.assertTrue(findings[8].false_p and findings[8].is_mitigated)
        self.assertTrue(findings[40].false_p and findings[40].is_mitigated)
        self.assertTrue(findings[6].out_of_scope)
        self.assertTrue(findings[7].out_of_scope)
        self.assertTrue(findings[36].out_of_scope)
        self.assertTrue(findings[3].is_mitigated)
        self.assertTrue(findings[35].is_mitigated)
        self.assertTrue(findings[45].is_mitigated)
