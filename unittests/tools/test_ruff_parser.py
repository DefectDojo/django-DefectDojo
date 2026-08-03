import json
import string

from dojo.models import Finding, Test
from dojo.tools.ruff.parser import RuffParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestRuffParser(DojoTestCase):
    def scan(self, filename):
        return get_unit_tests_scans_path("ruff") / filename

    def parse(self, filename):
        with self.scan(filename).open(encoding="utf-8") as file:
            return list(RuffParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = RuffParser()
        self.assertEqual(["Ruff Scan"], parser.get_scan_types())
        self.assertEqual("Ruff Scan", parser.get_label_for_scan_types("Ruff Scan"))
        self.assertIn("flake8-bandit", parser.get_description_for_scan_types("Ruff Scan"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("ruff_no_vuln.sarif")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("ruff_one_vuln.sarif")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `ruff check --select S --output-format sarif` run."""
        findings = self.parse("ruff_one_vuln.sarif")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("S324", finding.vuln_id_from_tool)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertIn("sample.py", finding.file_path)
        self.assertTrue(finding.static_finding)

    def test_many_vuln(self):
        findings = self.parse("ruff_many_vuln.sarif")
        self.assertEqual(9, len(findings))
        self.assertEqual(
            ["S105", "S107", "S301", "S307", "S311", "S324", "S501", "S602", "S608"],
            sorted(f.vuln_id_from_tool for f in findings),
        )

    def test_only_the_security_ruleset_is_imported(self):
        """
        The point of this parser: Ruff is mostly a style linter.

        This fixture is a real `ruff check --select ALL` run over the same file - 35 results across
        the ANN, CPY, D, EXE and S families. Only the 9 flake8-bandit ones may be imported; letting
        the rest through would bury real findings under lint opinions.
        """
        raw = json.loads(self.scan("ruff_mixed_rulesets.sarif").read_text(encoding="utf-8"))
        all_ids = [r.get("ruleId") for r in raw["runs"][0]["results"]]
        self.assertEqual(35, len(all_ids))
        self.assertTrue({"ANN", "CPY", "D", "EXE"} <= {i.rstrip(string.digits) for i in all_ids})

        findings = self.parse("ruff_mixed_rulesets.sarif")
        self.assertEqual(9, len(findings))
        for finding in findings:
            self.assertRegex(finding.vuln_id_from_tool, r"^S\d+$")

    def test_the_filter_also_applies_on_the_get_tests_path(self):
        """
        SarifParser exposes get_tests as well as get_findings, and builds findings separately.

        Filtering only one of the two would let the whole style ruleset through whenever DefectDojo
        took the other path.
        """
        with self.scan("ruff_mixed_rulesets.sarif").open(encoding="utf-8") as file:
            tests = RuffParser().get_tests("Ruff Scan", file)
        self.assertEqual(1, len(tests))
        self.assertEqual(9, len(tests[0].findings))
        for finding in tests[0].findings:
            self.assertRegex(finding.vuln_id_from_tool, r"^S\d+$")

    def test_severity_is_uniformly_high_and_that_is_the_tool_not_the_parser(self):
        """
        Ruff reports every rule at SARIF level "error" and sets no security-severity property.

        So all findings land at High. That is Ruff's own reporting, not a level this parser picked,
        and it is stated in the docs so nobody reads the uniformity as a mapping bug.
        """
        raw = json.loads(self.scan("ruff_many_vuln.sarif").read_text(encoding="utf-8"))
        self.assertEqual({"error"}, {r.get("level") for r in raw["runs"][0]["results"]})
        self.assertNotIn("security-severity", json.dumps(raw))

        self.assertEqual({"High"}, {f.severity for f in self.parse("ruff_many_vuln.sarif")})

    def test_the_sample_source_is_committed_alongside_the_fixtures(self):
        """
        The scanned sample is committed as .txt, not .py.

        A .py fixture would be linted as project code and would need a ruff.toml exemption, which
        this change deliberately does not make.
        """
        sample = self.scan("sample_insecure_source.txt")
        self.assertTrue(sample.is_file())
        self.assertIn("hashlib.md5", sample.read_text(encoding="utf-8"))
        self.assertFalse(self.scan("sample_insecure_source.py").exists())
