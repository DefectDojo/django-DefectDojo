from datetime import date

from dojo.models import Test
from dojo.tools.dependency_track.parser import DependencyTrackParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDependencyTrackParser(DojoTestCase):

    def test_dependency_track_parser_with_empty_list_for_findings_key_has_no_findings(self):
        with (
            get_unit_tests_scans_path("dependency_track") / "no_findings_because_findings_key_is_empty_list.json").open(encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_dependency_track_parser_with_missing_findings_key_has_no_findings(self):
        with (
            get_unit_tests_scans_path("dependency_track") / "no_findings_because_findings_key_is_missing.json").open(encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_dependency_track_parser_with_null_findings_key_has_no_findings(self):
        with (
            get_unit_tests_scans_path("dependency_track") / "no_findings_because_findings_key_is_null.json").open(encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_dependency_track_parser_has_many_findings(self):
        with (
            get_unit_tests_scans_path("dependency_track") / "many_findings.json").open(encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(4, len(findings))

            self.assertIsNone(findings[0].unsaved_vulnerability_ids)
            self.assertIsNone(findings[1].unsaved_vulnerability_ids)
            self.assertEqual(1, len(findings[2].unsaved_vulnerability_ids))
            self.assertEqual("CVE-2016-2097", findings[2].unsaved_vulnerability_ids[0])
            self.assertEqual("8d7f5fcd-210b-491d-a29e-904c2e01b281:3e52f829-3317-48c3-bde1-342c610bd223:900991f6-335a-49cb-9bf6-87b545f960ce", findings[2].unique_id_from_tool)
            self.assertEqual("900991f6-335a-49cb-9bf6-87b545f960ce", findings[2].vuln_id_from_tool)
            self.assertTrue(findings[2].false_p)
            self.assertTrue(findings[2].is_mitigated)
            self.assertFalse(findings[2].active)
            self.assertEqual(1, len(findings[3].unsaved_vulnerability_ids))
            self.assertEqual("CVE-2016-2097", findings[3].unsaved_vulnerability_ids[0])

    def test_dependency_track_parser_has_one_finding(self):
        with (
            get_unit_tests_scans_path("dependency_track") / "one_finding.json").open(encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            self.assertEqual(
                "ca4f2da9-0fad-4a13-92d7-f627f3168a56:b815b581-fec1-4374-a871-68862a8f8d52:115b80bb-46c4-41d1-9f10-8a175d4abb46",
                findings[0].unique_id_from_tool,
            )
            self.assertEqual(
                "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                findings[0].cvssv3,
            )
            self.assertEqual(
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N",
                findings[0].cvssv4,
            )
            self.assertIn("https://example.com", findings[0].references)
            self.assertIn("https://example.org", findings[0].references)
            self.assertEqual(date(2025, 7, 11), findings[0].publish_date)

    def test_dependency_track_parser_v3_8_0(self):
        with (
            get_unit_tests_scans_path("dependency_track") / "dependency_track_3.8.0_2021-01-18.json").open(encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(9, len(findings))
            self.assertTrue(all(item.file_path is not None for item in findings))
            self.assertTrue(all(item.vuln_id_from_tool is not None for item in findings))
            self.assertTrue(all(item.unique_id_from_tool is not None for item in findings))

    def test_dependency_track_parser_findings_with_alias(self):
        with (
            get_unit_tests_scans_path("dependency_track") / "many_findings_with_alias.json").open(encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(12, len(findings))
            self.assertTrue(all(item.file_path is not None for item in findings))
            self.assertTrue(all(item.unique_id_from_tool is not None for item in findings))
            self.assertTrue(all(item.vuln_id_from_tool is not None for item in findings))
            self.assertTrue(all(item.unique_id_from_tool is not None for item in findings))
            self.assertIn("CVE-2022-42004", findings[0].unsaved_vulnerability_ids)
            self.assertIn("DSA-5283-1", findings[0].unsaved_vulnerability_ids)
            self.assertIn("GHSA-rgv9-q543-rqg4", findings[0].unsaved_vulnerability_ids)

    def test_dependency_track_parser_findings_with_empty_alias(self):
        with (
            get_unit_tests_scans_path("dependency_track") / "many_findings_with_empty_alias.json").open(encoding="utf-8",
        ) as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(12, len(findings))
            self.assertIn("CVE-2022-2053", findings[11].unsaved_vulnerability_ids)

    def test_dependency_track_parser_findings_with_cvssV3_score(self):
        with (get_unit_tests_scans_path("dependency_track") / "many_findings_with_cvssV3_score.json").open(encoding="utf-8") as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(12, len(findings))
        self.assertTrue(all(item.file_path is not None for item in findings))
        self.assertTrue(all(item.unique_id_from_tool is not None for item in findings))
        self.assertTrue(all(item.vuln_id_from_tool is not None for item in findings))
        self.assertTrue(all(item.unique_id_from_tool is not None for item in findings))
        self.assertIn("CVE-2022-42004", findings[0].unsaved_vulnerability_ids)
        self.assertEqual(8.3, findings[0].cvssv3_score)

    def test_dependency_track_parser_findings_with_epss_score(self):
        with (get_unit_tests_scans_path("dependency_track") / "dependency_track_4.10_2024_02_11.json").open(encoding="utf-8") as testfile:
            parser = DependencyTrackParser()
            findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        self.assertEqual(0.00043, findings[0].epss_score)
        self.assertEqual(0.07756, findings[0].epss_percentile)
        self.assertEqual(4.2, findings[0].cvssv3_score)
        self.assertIn("CVE-2023-45803", findings[0].unsaved_vulnerability_ids)
