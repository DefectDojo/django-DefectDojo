from dojo.models import Test
from dojo.tools.bomber.parser import BomberParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestBomberParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("bomber") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = BomberParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("bomber") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = BomberParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Critical", finding.severity)
            self.assertEqual("CVE-2018-14719", finding.vuln_id_from_tool)
            self.assertEqual(["CVE-2018-14719"], finding.unsaved_vulnerability_ids)
            self.assertEqual("com.fasterxml.jackson.core/jackson-databind", finding.component_name)
            self.assertEqual("2.9.4", finding.component_version)
            self.assertIn("**Provider:** osv", finding.description)
            self.assertIn("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.4", finding.description)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("bomber") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = BomberParser().get_findings(testfile, Test())
            self.assertEqual(6, len(findings))

            with self.subTest("bomber's MODERATE maps to Medium, not to a default"):
                self.assertEqual(1, len([f for f in findings if f.severity == "Critical"]))
                self.assertEqual(3, len([f for f in findings if f.severity == "High"]))
                self.assertEqual(2, len([f for f in findings if f.severity == "Medium"]))

            with self.subTest("every finding is attributed to the same component"):
                self.assertEqual(
                    {"com.fasterxml.jackson.core/jackson-databind"},
                    {f.component_name for f in findings},
                )
                self.assertEqual({"2.9.4"}, {f.component_version for f in findings})

            with self.subTest("each advisory carries its CVE"):
                for finding in findings:
                    self.assertEqual([finding.vuln_id_from_tool], finding.unsaved_vulnerability_ids)

    def test_purl_is_split_into_component_and_version(self):
        parser = BomberParser()
        self.assertEqual(
            ("com.fasterxml.jackson.core/jackson-databind", "2.9.4"),
            parser._split_purl("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.4"),
        )
        self.assertEqual(("lodash", "4.17.19"), parser._split_purl("pkg:npm/lodash@4.17.19"))
        self.assertEqual((None, None), parser._split_purl(None))

    def test_non_cve_advisory_ids_are_not_recorded_as_cves(self):
        """Some providers return a GHSA id where OSV returns a CVE."""
        parser = BomberParser()
        finding = parser._to_finding(
            {"id": "GHSA-1234-5678-9abc", "title": "advisory", "cve": "GHSA-1234-5678-9abc", "severity": "HIGH"},
            "pkg:npm/lodash@4.17.19", "lodash", "4.17.19", "ossindex", Test(),
        )
        self.assertEqual("GHSA-1234-5678-9abc", finding.vuln_id_from_tool)
        self.assertFalse(hasattr(finding, "unsaved_vulnerability_ids") and finding.unsaved_vulnerability_ids)
