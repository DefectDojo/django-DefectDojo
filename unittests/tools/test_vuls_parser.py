from dojo.models import Test
from dojo.tools.vuls.parser import VulsParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestVulsParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("vuls") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = VulsParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("vuls") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = VulsParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("CVE-2026-11001", finding.vuln_id_from_tool)
            self.assertEqual(["CVE-2026-11001"], finding.unsaved_vulnerability_ids)
            self.assertEqual("Critical", finding.severity)
            self.assertEqual("openssl", finding.component_name)
            self.assertEqual(122, finding.cwe)
            self.assertEqual(9.8, finding.cvssv3_score)
            self.assertIn("CVSS:3.1/", finding.cvssv3)

            with self.subTest("the fix and the host are recorded"):
                self.assertIn("**Fixed in:** 3.0.14-1", finding.description)
                self.assertIn("**Server:** sample-host", finding.description)
                self.assertIn("**Platform:** debian 13", finding.description)

            with self.subTest("exploit and KEV signals are surfaced"):
                self.assertIn("**Known exploited:**", finding.description)
                self.assertIn("**Public exploits known:** 2", finding.description)

            with self.subTest("the tracker link becomes the mitigation"):
                self.assertIn("security-tracker", finding.mitigation)

    def test_parse_many_findings(self):
        """A CVE affecting two packages is two things to upgrade, so it becomes two Findings."""
        with (get_unit_tests_scans_path("vuls") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = VulsParser().get_findings(testfile, Test())
            self.assertEqual(5, len(findings))

            with self.subTest("severity follows the CVSS bands"):
                self.assertEqual(
                    {
                        "CVE-2026-11001": "Critical",
                        "CVE-2026-11002": "High",
                        "CVE-2026-11003": "Medium",
                        "CVE-2026-11004": "Low",
                    },
                    {f.vuln_id_from_tool: f.severity for f in findings},
                )

            with self.subTest("the two-package CVE is split by component"):
                shared = [f for f in findings if f.vuln_id_from_tool == "CVE-2026-11002"]
                self.assertEqual(2, len(shared))
                self.assertEqual({"curl", "libcurl4"}, {f.component_name for f in shared})

            with self.subTest("a package with no fix says so"):
                unfixed = next(f for f in findings if f.component_name == "zlib1g")
                self.assertIn("**Not fixed yet:** True", unfixed.description)

            with self.subTest("every finding carries its CVE as a vulnerability id"):
                for finding in findings:
                    self.assertEqual([finding.vuln_id_from_tool], finding.unsaved_vulnerability_ids)

    def test_the_highest_score_across_sources_wins(self):
        """Vuls reports one CveContent per source and they disagree; the highest is used."""
        parser = VulsParser()
        score, kind, word = parser._best_score([
            {"cvss3Score": 5.0, "cvss3Severity": "MEDIUM"},
            {"cvss3Score": 8.1, "cvss3Severity": "HIGH"},
            {"cvss2Score": 10.0, "cvss2Severity": "HIGH"},
        ])
        self.assertEqual(10.0, score)
        self.assertEqual("CVSS 2.0", kind)
        self.assertEqual("HIGH", word)

        with self.subTest("no score at all is Info rather than an invented middle"):
            self.assertEqual((0.0, None, None), parser._best_score([{"cvss3Score": 0}]))
            self.assertEqual("Info", parser._severity_from_score(0.0))

    def test_cve_contents_accepts_both_shapes(self):
        """CveContents maps a source to either one CveContent or a list of them."""
        parser = VulsParser()
        flattened = parser._flatten_contents({
            "nvd3": [{"cvss3Score": 7.5}],
            "debian": {"cvss3Score": 6.0},
        })
        self.assertEqual(2, len(flattened))
        self.assertEqual(7.5, parser._best_score(flattened)[0])
