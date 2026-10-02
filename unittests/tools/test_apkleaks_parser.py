import io
import json

from dojo.models import Finding, Test
from dojo.tools.apkleaks.parser import ApkleaksParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestApkleaksParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("apkleaks") / filename).open(encoding="utf-8") as file:
            return list(ApkleaksParser().get_findings(file, Test()))

    def report(self, filename):
        with (get_unit_tests_scans_path("apkleaks") / filename).open(encoding="utf-8") as file:
            return json.load(file)

    def test_scan_type_metadata(self):
        parser = ApkleaksParser()
        self.assertEqual(["APKLeaks Scan"], parser.get_scan_types())
        self.assertEqual("APKLeaks Scan", parser.get_label_for_scan_types("APKLeaks Scan"))
        self.assertIn("apkleaks", parser.get_description_for_scan_types("APKLeaks Scan"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("apkleaks_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("apkleaks_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """
        Mapping of the floor case: a clean app still reports one match.

        The only pattern that fires is LinkFinder, on the XML namespace URL that every Android
        manifest declares.
        """
        findings = self.parse("apkleaks_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("LinkFinder found in com.example.genericapp", finding.title)
        self.assertEqual("LinkFinder", finding.vuln_id_from_tool)
        self.assertEqual("com.example.genericapp", finding.component_name)
        self.assertEqual("Medium", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(1, finding.nb_occurences)

        self.assertIn("**Pattern:** LinkFinder", finding.description)
        self.assertIn("**Matches:** 1", finding.description)
        self.assertIn("schemas.android.com", finding.description)

    def test_no_source_position(self):
        """APKLeaks reports no file or line, only the matched string."""
        finding = self.parse("apkleaks_one_vuln.json")[0]
        self.assertIsNone(getattr(finding, "file_path", None))
        self.assertIsNone(getattr(finding, "line", None))

    def test_many_vuln(self):
        findings = self.parse("apkleaks_many_vuln.json")
        self.assertEqual(6, len(findings))
        for finding in findings:
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("com.example.genericapp", finding.component_name)

    def test_many_vuln_patterns(self):
        findings = self.parse("apkleaks_many_vuln.json")
        self.assertEqual(
            [
                "Firebase",
                "Generic_API_Key",
                "Generic_Secret",
                "Google_API_Key",
                "IP_Address",
                "LinkFinder",
            ],
            sorted(finding.vuln_id_from_tool for finding in findings),
        )

    def test_one_finding_per_pattern_not_per_match(self):
        """
        A pattern with several matches stays one finding, with the count in nb_occurences.

        APKLeaks gives no file or line, so a finding per match would differ only by the matched
        string - which would put secret material into titles and emit a finding per URL for the
        link patterns. The many_vuln report holds 10 matches across 6 patterns.
        """
        report = self.report("apkleaks_many_vuln.json")
        self.assertEqual(6, len(report["results"]))
        self.assertEqual(10, sum(len(r["matches"]) for r in report["results"]))

        findings = self.parse("apkleaks_many_vuln.json")
        self.assertEqual(6, len(findings))

        link_finder = next(f for f in findings if f.vuln_id_from_tool == "LinkFinder")
        self.assertEqual(5, link_finder.nb_occurences)
        self.assertIn("**Matches:** 5", link_finder.description)
        self.assertIn("api.example.com", link_finder.description)

    def test_matches_are_kept_as_evidence(self):
        findings = self.parse("apkleaks_many_vuln.json")
        firebase = next(f for f in findings if f.vuln_id_from_tool == "Firebase")
        self.assertEqual(1, firebase.nb_occurences)
        self.assertIn("firebaseio.com", firebase.description)

    def test_severity_is_a_documented_constant(self):
        """
        APKLeaks grades nothing, so every finding imports at one level.

        Its pattern set is user-extensible, so a per-rule ranking shipped in the parser would be
        guesswork that goes stale as soon as someone adds a pattern.
        """
        findings = self.parse("apkleaks_many_vuln.json")
        self.assertEqual({"Medium"}, {finding.severity for finding in findings})

    def test_report_without_a_package(self):
        report = io.StringIO(json.dumps({"results": [{"name": "Google_API_Key", "matches": ["x"]}]}))
        finding = list(ApkleaksParser().get_findings(report, Test()))[0]
        self.assertEqual("Google_API_Key", finding.title)
        self.assertIsNone(finding.component_name)

    def test_pattern_with_no_matches(self):
        """A pattern reported with an empty match list still yields one finding."""
        report = io.StringIO(json.dumps({
            "package": "com.example.genericapp",
            "results": [{"name": "Some_Pattern", "matches": []}],
        }))
        finding = list(ApkleaksParser().get_findings(report, Test()))[0]
        self.assertEqual("**Pattern:** Some_Pattern\n**Package:** com.example.genericapp\n**Matches:** 0",
                         finding.description)
        self.assertEqual(1, finding.nb_occurences)

    def test_absent_results_key(self):
        self.assertEqual(
            [],
            list(ApkleaksParser().get_findings(io.StringIO('{"package": "a"}'), Test())),
        )

    def test_wrong_shape_is_rejected(self):
        with self.assertRaises(TypeError):
            list(ApkleaksParser().get_findings(io.StringIO("[]"), Test()))
        with self.assertRaises(TypeError):
            list(ApkleaksParser().get_findings(io.StringIO('{"results": ["x"]}'), Test()))
