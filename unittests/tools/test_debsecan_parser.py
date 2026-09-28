import io

from dojo.models import Test
from dojo.tools.debsecan.parser import DebsecanParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDebsecanParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("debsecan") / "no_findings.txt").open(encoding="utf-8") as testfile:
            findings = DebsecanParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("debsecan") / "one_finding.txt").open(encoding="utf-8") as testfile:
            findings = DebsecanParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("CVE-2026-13595", finding.vuln_id_from_tool)
            self.assertEqual(["CVE-2026-13595"], finding.unsaved_vulnerability_ids)
            self.assertEqual("bsdutils", finding.component_name)
            self.assertEqual("1:2.41-5", finding.component_version)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("CVE-2026-13595: bsdutils", finding.title)

            with self.subTest("the source package and the fix are recorded"):
                self.assertIn("**Built from:** util-linux 2.41-5", finding.description)
                self.assertIn("fixed in unstable", finding.description)
                self.assertIn("util-linux 2.42.2-1", finding.mitigation)

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("debsecan") / "many_findings.txt").open(encoding="utf-8") as testfile:
            findings = DebsecanParser().get_findings(testfile, Test())
            self.assertEqual(8, len(findings))

            with self.subTest("every entry resolves a CVE and an installed package"):
                for finding in findings:
                    self.assertTrue(finding.vuln_id_from_tool.startswith("CVE-"))
                    self.assertIsNotNone(finding.component_name)
                    self.assertEqual([finding.vuln_id_from_tool], finding.unsaved_vulnerability_ids)

            with self.subTest("several packages are represented, not just the first block"):
                self.assertGreater(len({f.component_name for f in findings}), 1)

            with self.subTest("a 'fixed on branch' line is kept alongside 'fixed in'"):
                branched = [f for f in findings if "fixed on branch" in (f.mitigation or "")]
                self.assertGreater(len(branched), 0)

    def test_parse_simple_format(self):
        """The simple format has the package on the CVE line and no further detail."""
        with (get_unit_tests_scans_path("debsecan") / "simple_format.txt").open(encoding="utf-8") as testfile:
            findings = DebsecanParser().get_findings(testfile, Test())
            self.assertEqual(8, len(findings))
            self.assertEqual("CVE-2026-13595", findings[0].vuln_id_from_tool)
            self.assertEqual("bsdutils", findings[0].component_name)
            self.assertIn("debsecan reported no fixed version", findings[0].description)

    def test_temp_identifiers_are_not_treated_as_cves(self):
        """
        Debsecan emits TEMP- ids for issues the Debian tracker has not got a CVE for yet.

        Those must not become vulnerability ids, or DefectDojo will try to enrich an id that no
        CVE database has ever heard of.
        """
        payload = "TEMP-0000000-ABCDEF\n  Some unfixed issue.\n  installed: samplepkg 1.0-1\n"
        findings = DebsecanParser().get_findings(io.StringIO(payload), Test())
        self.assertEqual(1, len(findings))
        self.assertEqual("TEMP-0000000-ABCDEF", findings[0].vuln_id_from_tool)
        self.assertFalse(findings[0].unsaved_vulnerability_ids)
