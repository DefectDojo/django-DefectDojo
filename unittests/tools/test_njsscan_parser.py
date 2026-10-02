import io
import json

from dojo.models import Finding, Test
from dojo.tools.njsscan.parser import NjsscanParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path, skip_unless_v3


class TestNjsscanParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("njsscan") / filename).open(encoding="utf-8") as file:
            return list(NjsscanParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = NjsscanParser()
        self.assertEqual(["njsscan Scan"], parser.get_scan_types())
        self.assertEqual("njsscan Scan", parser.get_label_for_scan_types("njsscan Scan"))
        self.assertIn("njsscan --json", parser.get_description_for_scan_types("njsscan Scan"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("njsscan_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("njsscan_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `njsscan --json` run over hash.js."""
        findings = self.parse("njsscan_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("node_md5", finding.title)
        self.assertEqual("node_md5", finding.vuln_id_from_tool)
        self.assertEqual("Medium", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual(327, finding.cwe)
        self.assertEqual("hash.js", finding.file_path)
        self.assertEqual(4, finding.line)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertIn("**Result message:** MD5 is a", finding.description)
        self.assertIn("**Scanned as:** nodejs", finding.description)
        self.assertIn("createHash('md5')", finding.description)

    def test_cwe_is_parsed_out_of_the_description(self):
        """
        The CWE arrives as a whole sentence, not a number.

        The metadata value is "CWE-327: Use of a Broken or Risky Cryptographic Algorithm", so the
        integer has to be extracted; the full text stays in the description.
        """
        finding = self.parse("njsscan_one_vuln.json")[0]
        self.assertEqual(327, finding.cwe)
        self.assertIn("CWE-327: Use of a Broken", finding.description)

    def test_many_vuln(self):
        findings = self.parse("njsscan_many_vuln.json")
        self.assertEqual(5, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertTrue(finding.static_finding)
            self.assertEqual("server.js", finding.file_path)

    def test_many_vuln_rules_cwes_and_lines(self):
        findings = self.parse("njsscan_many_vuln.json")
        located = sorted((f.title, f.line, f.cwe, f.severity) for f in findings)
        self.assertEqual(
            [
                ("eval_nodejs", 14, 95, "High"),
                ("express_xss", 14, 79, "High"),
                ("express_xss", 18, 79, "High"),
                ("generic_os_command_exec", 8, 78, "High"),
                ("node_md5", 18, 327, "Medium"),
            ],
            located,
        )

    def test_many_vuln_one_rule_matching_twice(self):
        """
        Output is grouped by rule, with a list of matches under each.

        express_xss matches two places in one file, and each match has to become its own finding -
        counting rules instead of matches would report four findings rather than five.
        """
        findings = self.parse("njsscan_many_vuln.json")
        xss = [f for f in findings if f.title == "express_xss"]
        self.assertEqual(2, len(xss))
        self.assertEqual([14, 18], sorted(f.line for f in xss))

    def test_many_vuln_multiline_match_reports_the_range(self):
        """
        A match spanning several lines reports match_lines as a [start, end] pair.

        The finding anchors to the start line, and the description keeps the range so the reader
        knows the match was not a single line.
        """
        findings = self.parse("njsscan_many_vuln.json")
        command_exec = next(f for f in findings if f.title == "generic_os_command_exec")
        self.assertEqual(8, command_exec.line)
        self.assertIn("**Lines:** 8-10", command_exec.description)

    def test_single_line_match_has_no_range_in_the_description(self):
        finding = self.parse("njsscan_one_vuln.json")[0]
        self.assertNotIn("**Lines:**", finding.description)

    def test_templates_section_is_parsed(self):
        """Template findings arrive in a second section, which must import as well."""
        report = io.StringIO(json.dumps({
            "errors": [],
            "njsscan_version": "0.4.3",
            "nodejs": {},
            "templates": {
                "handlebars_triple_brace": {
                    "metadata": {
                        "cwe": "CWE-79: Improper Neutralization of Input During Web Page Generation",
                        "description": "Triple brace disables escaping.",
                        "severity": "WARNING",
                    },
                    "files": [{
                        "file_path": "views/index.hbs",
                        "match_lines": [3, 3],
                        "match_position": [5, 20],
                        "match_string": "{{{ body }}}",
                    }],
                },
            },
        }))
        findings = list(NjsscanParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("handlebars_triple_brace", findings[0].title)
        self.assertEqual("views/index.hbs", findings[0].file_path)
        self.assertEqual(79, findings[0].cwe)
        self.assertIn("**Scanned as:** templates", findings[0].description)

    def test_severity_map(self):
        """Severity reuses Semgrep's vocabulary, so the mapping matches that parser's."""
        parser = NjsscanParser()
        for level, expected in [
            ("ERROR", "High"),
            ("WARNING", "Medium"),
            ("INFO", "Low"),
            ("CRITICAL", "Critical"),
        ]:
            self.assertEqual(expected, parser.convert_severity(level))

        # A rule that omits severity is reported rather than dropped.
        self.assertEqual("Info", parser.convert_severity(None))

        # An unrecognised level is loud, matching the Semgrep parser rather than guessing.
        with self.assertRaises(ValueError):
            parser.convert_severity("SEVERE")

    def test_missing_cwe_is_none(self):
        parser = NjsscanParser()
        self.assertIsNone(parser.extract_cwe(None))
        self.assertIsNone(parser.extract_cwe("no identifier here"))
        self.assertEqual(78, parser.extract_cwe("CWE-78: OS Command Injection"))

    def test_snippet_workaround_for_rendering_bug(self):
        """
        A snippet containing "<![" breaks rendering, so it is spaced out with a note.

        Same guard the Semgrep parser applies for issue #8435; njsscan snippets are raw source and
        can contain the same sequence.
        """
        report = io.StringIO(json.dumps({
            "nodejs": {
                "some_rule": {
                    "metadata": {"severity": "ERROR", "description": "d"},
                    "files": [{
                        "file_path": "a.js",
                        "match_lines": [1, 1],
                        "match_string": "const x = '<![CDATA[y]]>';",
                    }],
                },
            },
        }))
        finding = list(NjsscanParser().get_findings(report, Test()))[0]
        self.assertIn("<! [CDATA", finding.description)
        self.assertIn("8435", finding.description)

    def test_empty_and_absent_sections(self):
        self.assertEqual([], list(NjsscanParser().get_findings(io.StringIO("{}"), Test())))
        self.assertEqual(
            [],
            list(NjsscanParser().get_findings(
                io.StringIO('{"nodejs": null, "templates": null}'), Test(),
            )),
        )

    def test_wrong_shape_is_rejected(self):
        with self.assertRaises(TypeError):
            list(NjsscanParser().get_findings(io.StringIO("[]"), Test()))

    @skip_unless_v3
    def test_locations(self):
        findings = self.parse("njsscan_one_vuln.json")
        locations = findings[0].unsaved_locations
        self.assertEqual(1, len(locations))
        self.assertEqual("code", locations[0].type)
        self.assertEqual("hash.js", locations[0].data["file_path"])
        self.assertEqual(4, locations[0].data["line"])
