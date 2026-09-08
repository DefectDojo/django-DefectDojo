import io

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
