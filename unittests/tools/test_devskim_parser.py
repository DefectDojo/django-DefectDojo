from dojo.models import Finding, Test
from dojo.tools.devskim.parser import DevskimParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDevskimParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("devskim") / filename).open(encoding="utf-8") as file:
            return list(DevskimParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = DevskimParser()
        self.assertEqual(["DevSkim Scan"], parser.get_scan_types())
        self.assertEqual("DevSkim Scan", parser.get_label_for_scan_types("DevSkim Scan"))
        self.assertIn("devskim analyze", parser.get_description_for_scan_types("DevSkim Scan"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("devskim_no_vuln.sarif")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("devskim_one_vuln.sarif")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `devskim analyze` run over hash.py."""
        findings = self.parse("devskim_one_vuln.sarif")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Weak/Broken Hash Algorithm", finding.title)
        self.assertEqual("DS126858", finding.vuln_id_from_tool)
        self.assertEqual("hash.py", finding.file_path)
        self.assertEqual(5, finding.line)
        self.assertIn(finding.severity, Finding.SEVERITIES)

        # DevSkim's SARIF carries no CWE taxonomy at all, which is why "DevSkim Scan" is registered
        # in HASHCODE_ALLOWS_NULL_CWE.
        # Finding.cwe is an IntegerField(default=0), so a rule with no CWE reads as 0.
        self.assertEqual(0, finding.cwe)

        # DevSkim publishes its rule categories as SARIF result tags.
        self.assertEqual(["Cryptography.BannedHashAlgorithm"], finding.unsaved_tags)

    def test_one_vuln_severity_comes_from_the_sarif_level(self):
        """
        DevSkim grades this rule "Critical" in its own vocabulary; it imports as High.

        DevSkim publishes two severities: the SARIF `level` (error here) and its own
        `DevSkimSeverity` property. Its rules carry no `security-severity` property, so the shared
        SARIF logic reads `level` alone, and error means High. Pinning that keeps the difference
        visible rather than surprising.
        """
        self.assertEqual("High", self.parse("devskim_one_vuln.sarif")[0].severity)

    def test_many_vuln(self):
        findings = self.parse("devskim_many_vuln.sarif")
        self.assertEqual(7, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            # Finding.cwe is an IntegerField(default=0), so no CWE reads as 0, not None.
            self.assertEqual(0, finding.cwe)

    def test_many_vuln_rules_and_lines(self):
        """Each rule keeps its own id, file and line across three languages."""
        findings = self.parse("devskim_many_vuln.sarif")
        located = sorted(
            (f.vuln_id_from_tool, f.file_path, f.line) for f in findings
        )
        self.assertEqual(
            [
                ("DS126858", "crypto.py", 6),
                ("DS126858", "crypto.py", 10),
                ("DS148264", "legacy.c", 16),
                ("DS154189", "legacy.c", 12),
                ("DS181021", "legacy.c", 11),
                ("DS185832", "legacy.c", 6),
                ("DS189424", "render.js", 6),
            ],
            located,
        )

    def test_many_vuln_same_rule_twice_in_one_file(self):
        """Two hits of one rule in one file stay two findings, one per source line."""
        findings = self.parse("devskim_many_vuln.sarif")
        weak_hash = [f for f in findings if f.vuln_id_from_tool == "DS126858"]
        self.assertEqual(2, len(weak_hash))
        self.assertEqual([6, 10], sorted(f.line for f in weak_hash))

    def test_many_vuln_severity_spread(self):
        """
        DevSkim's three SARIF levels survive as three distinct severities.

        note maps to Info, warning to Medium and error to High, so a change that flattened them to
        one value would fail here.
        """
        findings = self.parse("devskim_many_vuln.sarif")
        by_rule = {finding.vuln_id_from_tool: finding.severity for finding in findings}
        self.assertEqual("Info", by_rule["DS189424"])
        self.assertEqual("Medium", by_rule["DS154189"])
        self.assertEqual("High", by_rule["DS181021"])
        self.assertEqual("High", by_rule["DS148264"])
        self.assertEqual({"Info", "Medium", "High"}, set(by_rule.values()))

    def test_many_vuln_titles(self):
        """Rule titles keep the specific banned function where DevSkim names it."""
        findings = self.parse("devskim_many_vuln.sarif")
        by_rule = {finding.vuln_id_from_tool: finding.title for finding in findings}
        self.assertEqual("Banned C function detected (strcpy)", by_rule["DS185832"])
        self.assertEqual("Banned C function detected (gets)", by_rule["DS181021"])
        self.assertEqual("Banned C function detected", by_rule["DS154189"])
        self.assertEqual("Review eval for untrusted data", by_rule["DS189424"])
