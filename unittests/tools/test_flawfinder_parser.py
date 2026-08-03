from dojo.models import Finding, Test
from dojo.tools.flawfinder.parser import FlawfinderParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestFlawfinderParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("flawfinder") / filename).open(encoding="utf-8") as file:
            return list(FlawfinderParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        """
        Flawfinder gets its own scan type rather than being imported as generic SARIF, so its findings
        stay separable from every other SARIF producer's.
        """
        parser = FlawfinderParser()
        self.assertEqual(["Flawfinder Scan"], parser.get_scan_types())
        self.assertEqual("Flawfinder Scan", parser.get_label_for_scan_types("Flawfinder Scan"))
        self.assertIn("flawfinder --sarif", parser.get_description_for_scan_types("Flawfinder Scan"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("flawfinder_no_vuln.sarif")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("flawfinder_one_vuln.sarif")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping of the single finding, from a real `flawfinder --sarif single.c` run."""
        findings = self.parse("flawfinder_one_vuln.sarif")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertIn("shell/system", finding.title)
        self.assertEqual("FF1044", finding.vuln_id_from_tool)

        # SARIF level "warning" maps to High through the shared SARIF logic.
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)

        # Flawfinder publishes its CWE mapping via SARIF rule relationships, which the shared parser
        # reads in preference to properties.
        self.assertEqual(78, finding.cwe)

        self.assertEqual("single.c", finding.file_path)
        self.assertEqual(3, finding.line)

    def test_many_vuln(self):
        findings = self.parse("flawfinder_many_vuln.sarif")
        self.assertEqual(4, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)

        rules = [finding.vuln_id_from_tool for finding in findings]
        self.assertEqual(["FF1013", "FF1001", "FF1016", "FF1014"], rules)

    def test_many_vuln_cwes_and_lines(self):
        """
        Each hit keeps its own CWE and source line.

        A rule carrying several CWEs (gets is CWE-120 and CWE-20) resolves to the last one the shared
        SARIF parser extracts, which is its documented behaviour rather than anything flawfinder-specific.
        """
        findings = self.parse("flawfinder_many_vuln.sarif")
        by_rule = {finding.vuln_id_from_tool: finding for finding in findings}

        self.assertEqual(120, by_rule["FF1013"].cwe)
        self.assertEqual(4, by_rule["FF1013"].line)

        self.assertEqual(120, by_rule["FF1001"].cwe)
        self.assertEqual(5, by_rule["FF1001"].line)
        self.assertIn("strcpy", by_rule["FF1001"].title)

        self.assertEqual(134, by_rule["FF1016"].cwe)
        self.assertEqual(6, by_rule["FF1016"].line)

        self.assertEqual(20, by_rule["FF1014"].cwe)
        self.assertEqual(7, by_rule["FF1014"].line)

        for finding in findings:
            self.assertEqual("vulnerable.c", finding.file_path)

    def test_many_vuln_severity_spread(self):
        """
        Flawfinder's risk levels survive as distinct severities rather than collapsing to one value.

        The statically-sized-array hit is reported at SARIF level "note" and lands on Info; the three
        dangerous-call hits are "warning" and land on High.
        """
        findings = self.parse("flawfinder_many_vuln.sarif")
        by_rule = {finding.vuln_id_from_tool: finding for finding in findings}

        self.assertEqual("Info", by_rule["FF1013"].severity)
        self.assertEqual("High", by_rule["FF1001"].severity)
        self.assertEqual("High", by_rule["FF1016"].severity)
        self.assertEqual("High", by_rule["FF1014"].severity)
