import io
import json

from dojo.models import Finding, Test
from dojo.tools.cwe_checker.parser import CweCheckerParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestCweCheckerParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("cwe_checker") / filename).open(encoding="utf-8") as file:
            return list(CweCheckerParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = CweCheckerParser()
        self.assertEqual(["cwe_checker Scan"], parser.get_scan_types())
        self.assertEqual("cwe_checker Scan", parser.get_label_for_scan_types("cwe_checker Scan"))
        self.assertIn("cwe_checker --json", parser.get_description_for_scan_types("cwe_checker Scan"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("cwe_checker_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("cwe_checker_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `cwe_checker --json` run over a stripped binary."""
        findings = self.parse("cwe_checker_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Use of Potentially Dangerous Function", finding.title)
        self.assertEqual(676, finding.cwe)
        self.assertEqual("CWE676", finding.vuln_id_from_tool)
        self.assertEqual("Medium", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertIn("strcpy", finding.description)
        self.assertIn("**Check:** CWE676", finding.description)
        self.assertIn("**Check version:** 0.1", finding.description)
        self.assertIn("**Details:** dangerous_function strcpy", finding.description)

    def test_no_source_position(self):
        """
        cwe_checker analyses a compiled binary, so a finding has no file or line.

        It is located by symbol and virtual address instead, which is why both are kept in the
        description rather than being dropped.
        """
        finding = self.parse("cwe_checker_one_vuln.json")[0]
        self.assertIsNone(getattr(finding, "file_path", None))
        self.assertIsNone(getattr(finding, "line", None))
        self.assertIn("**Symbols:**", finding.description)
        self.assertIn("**Addresses:**", finding.description)

    def test_addresses_are_shown_in_hexadecimal_too(self):
        """
        Addresses arrive as decimal strings; a disassembler shows hexadecimal.

        Both forms are printed so the finding can be matched against a disassembly without the
        reader converting by hand.
        """
        finding = self.parse("cwe_checker_one_vuln.json")[0]
        self.assertIn("**Addresses:** 0x401155 (4198741)", finding.description)

    def test_title_is_the_parenthetical_and_is_not_repeated_in_the_body(self):
        """
        Descriptions lead with the check name in parentheses; that becomes the title.

        The remaining detail is the body, so the name is not printed twice.
        """
        finding = self.parse("cwe_checker_one_vuln.json")[0]
        self.assertEqual("Use of Potentially Dangerous Function", finding.title)
        self.assertFalse(finding.description.startswith("(Use of Potentially Dangerous Function)"))

    def test_many_vuln(self):
        findings = self.parse("cwe_checker_many_vuln.json")
        self.assertEqual(9, len(findings))
        for finding in findings:
            self.assertEqual("Medium", finding.severity)
            self.assertTrue(finding.static_finding)

    def test_many_vuln_checks_and_cwes(self):
        findings = self.parse("cwe_checker_many_vuln.json")
        pairs = sorted({(f.vuln_id_from_tool, f.cwe) for f in findings})
        self.assertEqual(
            [
                ("CWE134", 134),
                ("CWE190", 190),
                ("CWE215", 215),
                ("CWE415", 415),
                ("CWE416", 416),
                ("CWE476", 476),
                ("CWE676", 676),
            ],
            pairs,
        )

    def test_many_vuln_same_check_at_different_addresses(self):
        """
        One check firing at three call sites stays three findings.

        Nothing but the address distinguishes them, so collapsing on the check name would lose two
        of the three unchecked allocations.
        """
        findings = self.parse("cwe_checker_many_vuln.json")
        null_deref = [f for f in findings if f.vuln_id_from_tool == "CWE476"]
        self.assertEqual(3, len(null_deref))
        self.assertEqual(3, len({f.description for f in null_deref}))

    def test_many_vuln_warning_without_a_location(self):
        """
        A whole-binary warning carries empty addresses, tids and symbols.

        CWE215 is reported against the file rather than a call site, so those sections are omitted
        instead of appearing empty.
        """
        findings = self.parse("cwe_checker_many_vuln.json")
        debug_info = next(f for f in findings if f.vuln_id_from_tool == "CWE215")
        self.assertEqual("Information Exposure Through Debug Information", debug_info.title)
        self.assertIn("The binary contains debug symbols.", debug_info.description)
        self.assertNotIn("**Addresses:**", debug_info.description)
        self.assertNotIn("**Symbols:**", debug_info.description)
        self.assertNotIn("**Term identifiers:**", debug_info.description)

    def test_severity_is_a_documented_constant(self):
        """
        cwe_checker grades nothing, so every finding imports at one level.

        There is no severity, score or confidence anywhere in its output; inventing a per-check
        ranking would be guesswork, so the docs page says to triage by CWE instead.
        """
        findings = self.parse("cwe_checker_many_vuln.json")
        self.assertEqual({"Medium"}, {finding.severity for finding in findings})

    def test_unknown_check_name(self):
        """A check name that is not of the CWEnnn form still imports, without a CWE."""
        report = io.StringIO(json.dumps([{
            "name": "Memory",
            "version": "0.1",
            "addresses": [],
            "tids": [],
            "symbols": [],
            "other": [],
            "description": "(Memory Analysis) something worth knowing",
        }]))
        findings = list(CweCheckerParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("Memory Analysis", findings[0].title)
        self.assertIsNone(findings[0].cwe)
        self.assertEqual("Memory", findings[0].vuln_id_from_tool)

    def test_description_without_a_parenthetical(self):
        report = io.StringIO(json.dumps([{
            "name": "CWE676",
            "description": "no leading parenthetical here",
        }]))
        finding = list(CweCheckerParser().get_findings(report, Test()))[0]
        self.assertEqual("CWE676", finding.title)
        self.assertIn("no leading parenthetical here", finding.description)

    def test_non_numeric_address_is_kept_verbatim(self):
        parser = CweCheckerParser()
        self.assertEqual("0x10 (16)", parser.format_addresses(["16"]))
        self.assertEqual("unknown", parser.format_addresses(["unknown"]))
        self.assertEqual("", parser.format_addresses(None))

    def test_empty_report(self):
        self.assertEqual([], list(CweCheckerParser().get_findings(io.StringIO("[]"), Test())))

    def test_wrong_shape_is_rejected(self):
        with self.assertRaises(TypeError):
            list(CweCheckerParser().get_findings(io.StringIO('{"warnings": []}'), Test()))
        with self.assertRaises(TypeError):
            list(CweCheckerParser().get_findings(io.StringIO("[1]"), Test()))
