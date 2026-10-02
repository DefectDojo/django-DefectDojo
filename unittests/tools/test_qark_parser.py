import io
import json

from dojo.models import Finding, Test
from dojo.tools.qark.parser import QarkParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path, skip_unless_v3


class TestQarkParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("qark") / filename).open(encoding="utf-8") as file:
            return list(QarkParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = QarkParser()
        self.assertEqual(["QARK Scan"], parser.get_scan_types())
        self.assertEqual("QARK Scan", parser.get_label_for_scan_types("QARK Scan"))
        self.assertIn("qark", parser.get_description_for_scan_types("QARK Scan"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("qark_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("qark_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """
        Full field mapping, from a real `qark --report-type json` run.

        The single issue is QARK's API-key pattern matching the RSA signing block, which is a false
        positive every signed APK can produce - useful here precisely because it exercises the
        INFO severity and the [line, column] pair.
        """
        findings = self.parse("qark_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Potential API Key found", finding.title)
        self.assertEqual("Potential API Key found", finding.vuln_id_from_tool)
        self.assertEqual("Info", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual(11, finding.line)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertIn("**Category:** file", finding.description)
        self.assertIn("**Line:** 11, column 0", finding.description)

    def test_build_path_is_stripped_from_file_paths(self):
        """
        QARK reports an absolute path through the build directory it happened to use.

        Everything up to and including its "/qark/" output marker is dropped, so the path is
        readable and stable rather than tied to one run's build directory.
        """
        finding = self.parse("qark_one_vuln.json")[0]
        self.assertEqual("META-INF/A.RSA", finding.file_path)
        self.assertNotIn("b_single", finding.file_path)

    def test_relative_path_helper(self):
        parser = QarkParser()
        self.assertEqual(
            "cfr/com/example/genericapp/MainActivity.java",
            parser.relative_path("/tmp/build/qark/cfr/com/example/genericapp/MainActivity.java"),
        )
        self.assertEqual("AndroidManifest.xml", parser.relative_path("/b/qark/AndroidManifest.xml"))
        # A path without the marker is reported as-is rather than guessed at.
        self.assertEqual("/elsewhere/App.java", parser.relative_path("/elsewhere/App.java"))
        self.assertIsNone(parser.relative_path(None))

    def test_many_vuln(self):
        findings = self.parse("qark_many_vuln.json")
        self.assertEqual(6, len(findings))
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertTrue(finding.static_finding)

    def test_many_vuln_names_and_severities(self):
        findings = self.parse("qark_many_vuln.json")
        pairs = sorted({(f.title, f.severity) for f in findings})
        self.assertEqual(
            [
                ("Exported tags", "Medium"),
                ("Logging found", "Medium"),
                ("Tap Jacking possible", "High"),
            ],
            pairs,
        )

    def test_same_issue_reported_by_both_decompilers(self):
        """
        QARK decompiles with fernflower AND cfr, and reports code issues from both.

        Two log calls therefore surface as four findings, under paths that differ only by the
        decompiler. They are reported faithfully rather than merged - the line numbers genuinely
        differ between decompiler outputs, so there is no single correct location to merge them to.
        """
        findings = self.parse("qark_many_vuln.json")
        logging = [f for f in findings if f.title == "Logging found"]
        self.assertEqual(4, len(logging))

        by_decompiler = {}
        for finding in logging:
            by_decompiler.setdefault(finding.file_path.split("/")[0], []).append(finding.line)
        self.assertEqual({"cfr", "fernflower"}, set(by_decompiler))
        self.assertEqual([17, 18], sorted(by_decompiler["fernflower"]))
        self.assertEqual([27, 28], sorted(by_decompiler["cfr"]))

    def test_manifest_issue_without_a_file_or_line(self):
        """A manifest-level issue can arrive with no file_object and no line_number."""
        findings = self.parse("qark_many_vuln.json")
        tap_jacking = next(f for f in findings if f.title == "Tap Jacking possible")
        self.assertIsNone(tap_jacking.file_path)
        self.assertIsNone(tap_jacking.line)
        self.assertEqual("High", tap_jacking.severity)
        self.assertIn("minSdkVersion", tap_jacking.description)

    def test_exploit_details_are_kept(self):
        """The apk_exploit_dict carries the affected component, which is worth reporting."""
        findings = self.parse("qark_many_vuln.json")
        exported = next(f for f in findings if f.title == "Exported tags")
        self.assertIn("**Package name:** com.example.genericapp", exported.description)
        self.assertIn("**Tag name:** .MainActivity", exported.description)

    def test_severity_map(self):
        parser = QarkParser()
        for level, expected in [("VULNERABILITY", "High"), ("WARNING", "Medium"), ("INFO", "Info")]:
            report = io.StringIO(json.dumps([{"name": "n", "severity": level}]))
            self.assertEqual(expected, list(parser.get_findings(report, Test()))[0].severity)

        # An unrecognised level is reported rather than dropped.
        report = io.StringIO(json.dumps([{"name": "n", "severity": "SOMETHING"}]))
        self.assertEqual("Medium", list(parser.get_findings(report, Test()))[0].severity)

    def test_line_number_shapes(self):
        parser = QarkParser()
        self.assertEqual(14, parser.first_line([14, 0]))
        self.assertEqual(14, parser.first_line(14))
        self.assertIsNone(parser.first_line(None))
        self.assertIsNone(parser.first_line([]))
        self.assertIsNone(parser.first_line(["x"]))

    def test_wrong_shape_is_rejected(self):
        with self.assertRaises(TypeError):
            list(QarkParser().get_findings(io.StringIO('{"issues": []}'), Test()))
        with self.assertRaises(TypeError):
            list(QarkParser().get_findings(io.StringIO("[1]"), Test()))

    @skip_unless_v3
    def test_locations(self):
        findings = self.parse("qark_one_vuln.json")
        locations = findings[0].unsaved_locations
        self.assertEqual(1, len(locations))
        self.assertEqual("code", locations[0].type)
        self.assertEqual("META-INF/A.RSA", locations[0].data["file_path"])
        self.assertEqual(11, locations[0].data["line"])
