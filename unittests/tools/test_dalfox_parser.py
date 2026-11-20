import io
import json

from django.conf import settings

from dojo.models import Test
from dojo.tools.dalfox.parser import DalfoxParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDalfoxParser(DojoTestCase):

    def test_parse_no_findings(self):
        """Dalfox writes an array holding only its trailing empty object when it finds nothing."""
        with (get_unit_tests_scans_path("dalfox") / "no_findings.json").open(encoding="utf-8") as testfile:
            findings = DalfoxParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("dalfox") / "one_finding.json").open(encoding="utf-8") as testfile:
            findings = DalfoxParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("High", finding.severity)
            self.assertEqual(79, finding.cwe)
            self.assertEqual("q", finding.param)
            self.assertEqual("V-inHTML-URL", finding.vuln_id_from_tool)
            self.assertFalse(finding.static_finding)
            self.assertTrue(finding.dynamic_finding)

            with self.subTest("the payload and the evidence are both kept"):
                self.assertIsNotNone(finding.payload)
                self.assertIn("**Payload:**", finding.description)
                self.assertIn("**Evidence:**", finding.description)
                self.assertIn("**Proof of concept:**", finding.description)

            with self.subTest("a verified result says so"):
                self.assertIn("Verified — payload executed", finding.description)

            if settings.V3_FEATURE_LOCATIONS:
                with self.subTest("the proof of concept URL becomes a location without the payload"):
                    self.assertEqual(1, len(finding.unsaved_locations))
                    location = finding.unsaved_locations[0]
                    self.assertEqual("url", location.type)
                    self.assertEqual("127.0.0.1", location.data["host"])
                    self.assertEqual(18080, location.data["port"])
                    self.assertEqual("", location.data["query"])
            else:
                # TODO: Delete this after the move to Locations
                with self.subTest("the proof of concept URL becomes an endpoint without the payload"):
                    self.assertEqual(1, len(finding.unsaved_endpoints))
                    endpoint = finding.unsaved_endpoints[0]
                    self.assertEqual("127.0.0.1", endpoint.host)
                    self.assertEqual(18080, endpoint.port)

    def test_parse_many_findings(self):
        """Dalfox grades a verified injection above one it only saw reflected."""
        with (get_unit_tests_scans_path("dalfox") / "many_findings.json").open(encoding="utf-8") as testfile:
            findings = DalfoxParser().get_findings(testfile, Test())
            self.assertEqual(9, len(findings))

            with self.subTest("V is High and R is Medium, from Dalfox's own severity field"):
                self.assertEqual(3, len([f for f in findings if f.severity == "High"]))
                self.assertEqual(6, len([f for f in findings if f.severity == "Medium"]))

            with self.subTest("the result type is recorded so the two are distinguishable"):
                verified = [f for f in findings if f.severity == "High"]
                reflected = [f for f in findings if f.severity == "Medium"]
                for finding in verified:
                    self.assertTrue(finding.vuln_id_from_tool.startswith("V-"))
                for finding in reflected:
                    self.assertTrue(finding.vuln_id_from_tool.startswith("R-"))

            with self.subTest("every finding names the injectable parameter and carries a CWE"):
                for finding in findings:
                    self.assertIn(finding.param, {"q", "name", "ref"})
                    self.assertEqual(79, finding.cwe)

            with self.subTest("repeated payloads against one parameter are all kept"):
                for_name = [f for f in findings if f.param == "name"]
                self.assertGreater(len(for_name), 1)
                self.assertEqual(len(for_name), len({f.payload for f in for_name}))

    def test_the_trailing_empty_object_is_never_a_finding(self):
        """Dalfox terminates its JSON array with {}, which would otherwise become a bare Finding."""
        payload = (
            '[{"type":"R","severity":"Medium","cwe":"CWE-79","param":"q","payload":"<x>",'
            '"data":"http://127.0.0.1:8080/?q=%3Cx%3E","message_str":"reflected"},{}]'
        )
        findings = DalfoxParser().get_findings(io.StringIO(payload), Test())
        self.assertEqual(1, len(findings))
        self.assertEqual("Medium", findings[0].severity)

    def test_parse_v3_no_findings(self):
        with (get_unit_tests_scans_path("dalfox") / "v3_no_findings.json").open(encoding="utf-8") as testfile:
            findings = DalfoxParser().get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_v3_one_finding(self):
        with (get_unit_tests_scans_path("dalfox") / "v3_one_finding.json").open(encoding="utf-8") as testfile:
            findings = DalfoxParser().get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Outdated JavaScript library: jQuery 1.7.2", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(1104, finding.cwe)
            self.assertEqual("I-OutdatedComponent", finding.vuln_id_from_tool)
            self.assertIsNone(finding.param)
            self.assertIsNone(finding.payload)
            self.assertEqual(finding.title, finding.component_name)
            self.assertIn("Informational - outdated or known-vulnerable component", finding.description)
            self.assertIn("**Detection method:** library", finding.description)
            self.assertNotIn("XSS in parameter", finding.title)
            self.assertNotIn("**Parameter:**", finding.description)

    def test_parse_v3_many_findings(self):
        with (get_unit_tests_scans_path("dalfox") / "v3_many_findings.json").open(encoding="utf-8") as testfile:
            report = json.load(testfile)
        findings = DalfoxParser().get_findings(io.StringIO(json.dumps(report)), Test())
        self.assertEqual(3, len(findings))
        for result, finding in zip(report["findings"], findings, strict=True):
            with self.subTest(result=result["inject_type"]):
                self.assertEqual(result["severity"], finding.severity)
                self.assertEqual(result["param"] or None, finding.param)
                self.assertEqual(result["payload"] or None, finding.payload)
                self.assertIn(result["type_description"], finding.description)
                self.assertIn(f"**Detection method:** {result['detection_method']}", finding.description)
                self.assertNotIn("payload executed", finding.description)
                if result.get("location"):
                    self.assertIn(f"**Location:** {result['location']}", finding.description)
                if result.get("confidence"):
                    self.assertIn(f"**Confidence:** {result['confidence']}", finding.description)
                    self.assertIn(f"**Confidence reason:** {result['confidence_reason']}", finding.description)
        self.assertEqual(["I-OutdatedComponent", "V-DOM-XSS", "V-inHTML"], [f.vuln_id_from_tool for f in findings])
        self.assertEqual([1104, 79, 79], [f.cwe for f in findings])

    def test_v3_type_labels_without_description(self):
        for result_type, label in (
            ("V", "Vulnerable — input is exploitable"),
            ("R", "Reflected — payload echoed but not verified"),
            ("A", "AST-detected DOM XSS — static JavaScript analysis"),
            ("I", "Informational — outdated or known-vulnerable component"),
        ):
            with self.subTest(result_type=result_type):
                report = {"findings": [{"type": result_type, "param": "q"}]}
                finding = DalfoxParser().get_findings(io.StringIO(json.dumps(report)), Test())[0]
                self.assertIn(f"**Result type:** {result_type} ({label})", finding.description)
                self.assertNotIn("payload executed", finding.description)

    def test_report_type_description_takes_precedence(self):
        result = {"type": "V", "type_description": "Report's own label", "param": "q"}
        for report in ([result], {"findings": [result]}):
            with self.subTest(report=report):
                finding = DalfoxParser().get_findings(io.StringIO(json.dumps(report)), Test())[0]
                self.assertIn("**Result type:** V (Report's own label)", finding.description)

    def test_invalid_report_shape(self):
        for report in ({}, {"meta": {}}, {"findings": None}, {"findings": {}}, {"findings": "invalid"}, None, 1, "invalid"):
            with self.subTest(report=report), self.assertRaisesRegex(ValueError, "Dalfox.*findings"):
                DalfoxParser().get_findings(io.StringIO(json.dumps(report)), Test())

    def test_non_object_items_are_skipped(self):
        result = {"type": "R", "param": "q", "severity": "Info"}
        for items in ([None, "invalid", 1, True, [], {}], [None, "invalid", 1, True, [], {}, result]):
            for report in (items, {"findings": items}):
                with self.subTest(report=report):
                    findings = DalfoxParser().get_findings(io.StringIO(json.dumps(report)), Test())
                    self.assertEqual(["q"] if result in items else [], [f.param for f in findings])

    def test_v3_library_advisories_have_distinct_components(self):
        with (get_unit_tests_scans_path("dalfox") / "v3_one_finding.json").open(encoding="utf-8") as testfile:
            report = json.load(testfile)
        other = dict(report["findings"][0], message_str="Outdated JavaScript library: Lodash 4.17.10")
        report["findings"].append(other)
        findings = DalfoxParser().get_findings(io.StringIO(json.dumps(report)), Test())
        self.assertEqual(2, len(findings))
        self.assertNotEqual(findings[0].component_name, findings[1].component_name)

    def test_v3_informational_title_without_message(self):
        report = {"findings": [{"type": "I", "inject_type": "OutdatedComponent"}]}
        finding = DalfoxParser().get_findings(io.StringIO(json.dumps(report)), Test())[0]
        self.assertEqual("Informational finding", finding.title)
        self.assertIsNone(finding.param)
