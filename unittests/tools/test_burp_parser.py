
from dojo.models import Test
from dojo.tools.burp.parser import BurpParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestBurpParser(DojoTestCase):

    def test_burp_with_one_vuln_has_one_finding(self):
        with (get_unit_tests_scans_path("burp") / "one_finding.xml").open(encoding="utf-8") as test_file:
            parser = BurpParser()
            findings = parser.get_findings(test_file, Test())
            self.validate_locations(findings)

            self.assertEqual(1, len(findings))
            self.assertEqual("1049088", findings[0].vuln_id_from_tool)
            self.assertEqual(3, len(self.get_unsaved_locations(findings[0])))

    def test_burp_with_multiple_vulns_has_multiple_findings(self):
        with (get_unit_tests_scans_path("burp") / "seven_findings.xml").open(encoding="utf-8") as test_file:
            parser = BurpParser()
            findings = parser.get_findings(test_file, Test())
            self.validate_locations(findings)
            self.assertEqual(7, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("5245344", finding.vuln_id_from_tool)
                self.assertEqual("Info", finding.severity)
                self.assertEqual("Frameable response (potential Clickjacking)", finding.title)

    def test_burp_with_one_vuln_with_blank_response(self):
        with (get_unit_tests_scans_path("burp") / "one_finding_with_blank_response.xml").open(encoding="utf-8") as test_file:
            parser = BurpParser()
            findings = parser.get_findings(test_file, Test())
            self.validate_locations(findings)

            self.assertEqual(1, len(findings))

            self.assertEqual("7121655797013284864", findings[0].unique_id_from_tool)
            self.assertEqual("1049088", findings[0].vuln_id_from_tool)
            self.assertEqual("SQL injection", findings[0].title)
            self.assertEqual(1, len(self.get_unsaved_locations(findings[0])))
            self.assertEqual("High", findings[0].severity)

    def test_burp_with_one_vuln_with_cwe(self):
        with (get_unit_tests_scans_path("burp") / "one_finding_with_cwe.xml").open(encoding="utf-8") as test_file:
            parser = BurpParser()
            findings = parser.get_findings(test_file, Test())
            self.validate_locations(findings)

            self.assertEqual(1, len(findings))

            self.assertEqual("456437653765735", findings[0].unique_id_from_tool)
            self.assertEqual("7340288", findings[0].vuln_id_from_tool)
            self.assertEqual("Cacheable HTTPS response", findings[0].title)
            self.assertEqual(524, findings[0].cwe)
            self.assertEqual([524, 525], findings[0].unsaved_cwes)
            self.assertEqual("Info", findings[0].severity)

    def test_burp_issue4399(self):
        with (get_unit_tests_scans_path("burp") / "issue4399.xml").open(encoding="utf-8") as test_file:
            parser = BurpParser()
            findings = parser.get_findings(test_file, Test())
            self.validate_locations(findings)
            # 20 Burp issue types, but the extension-generated type (0x08000000)
            # covers 8 distinct vulnerabilities that must not be merged together.
            self.assertEqual(27, len(findings))
            by_title = {finding.title: finding for finding in findings}
            self.assertEqual(len(findings), len(by_title))
            with self.subTest("Unencrypted communications"):
                finding = by_title["Unencrypted communications"]
                self.assertEqual("4060931308708695040", finding.unique_id_from_tool)
                self.assertEqual("16777728", finding.vuln_id_from_tool)
                self.assertEqual(326, finding.cwe)
                self.assertEqual("Low", finding.severity)
            with self.subTest("Input returned in response (reflected)"):
                finding = by_title["Input returned in response (reflected)"]
                self.assertEqual("3648136005422773248", finding.unique_id_from_tool)
                self.assertEqual("4197376", finding.vuln_id_from_tool)
                self.assertEqual(20, finding.cwe)
                self.assertEqual("Info", finding.severity)
            with self.subTest("External service interaction (HTTP)"):
                finding = by_title["External service interaction (HTTP)"]
                self.assertEqual("5394761637085678592", finding.unique_id_from_tool)
                self.assertEqual("3146256", finding.vuln_id_from_tool)
                self.assertEqual(918, finding.cwe)
                self.assertEqual("High", finding.severity)

    def test_burp_extension_generated_issues_are_not_merged(self):
        """
        Every Burp extension-generated issue carries the same <type> (0x08000000),
        so aggregating on type alone collapsed unrelated extension findings into a
        single finding. See #6369.
        """
        with (get_unit_tests_scans_path("burp") / "issue4399.xml").open(encoding="utf-8") as test_file:
            parser = BurpParser()
            findings = parser.get_findings(test_file, Test())
        extension_findings = [f for f in findings if f.vuln_id_from_tool == "134217728"]
        self.assertEqual(
            [
                "Browser cross-site scripting filter misconfiguration",
                "Content Sniffing not disabled",
                "Detailed Error Messages Revealed",
                "Interesting Header(s)",
                "Lack or Misconfiguration of Security Header(s)",
                "Web Cache Misconfiguration",
                "[Vulners] Software detected",
                "[Vulners] Vulnerable Software detected",
            ],
            sorted(f.title for f in extension_findings),
        )
        # Burp's own checks map one title per type, so they stay aggregated as before.
        native_titles_per_type = {}
        for finding in findings:
            if finding.vuln_id_from_tool != "134217728":
                native_titles_per_type.setdefault(finding.vuln_id_from_tool, []).append(finding.title)
        for vuln_id, titles in native_titles_per_type.items():
            self.assertEqual(1, len(titles), f"type {vuln_id} produced more than one finding: {titles}")
