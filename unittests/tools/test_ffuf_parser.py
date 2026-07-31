import io
import json

from dojo.models import Finding, Test
from dojo.tools.ffuf.parser import FfufParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestFfufParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("ffuf") / filename).open(encoding="utf-8") as file:
            return list(FfufParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = FfufParser()
        self.assertEqual(["ffuf Scan"], parser.get_scan_types())
        self.assertEqual("ffuf Scan", parser.get_label_for_scan_types("ffuf Scan"))
        self.assertIn("ffuf -of json", parser.get_description_for_scan_types("ffuf Scan"))

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("ffuf_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("ffuf_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `ffuf -of json` run against a local target."""
        findings = self.parse("ffuf_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("HTTP 301: /admin", finding.title)
        self.assertEqual("Info", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertTrue(finding.dynamic_finding)
        self.assertFalse(finding.static_finding)

        self.assertIn("**Status:** 301", finding.description)
        self.assertIn("**Payload:** admin", finding.description)
        self.assertIn("**Response length:** 169", finding.description)
        self.assertIn("**Redirects to:** http://wave3target/admin/", finding.description)

    def test_the_url_becomes_an_endpoint(self):
        """
        A full URL maps to an endpoint rather than a file path.

        This is a DAST-style tool: nothing here is a source position.
        """
        finding = self.parse("ffuf_one_vuln.json")[0]
        self.assertEqual(1, len(finding.unsaved_endpoints))
        self.assertIsNone(getattr(finding, "file_path", None))
        self.assertIsNone(getattr(finding, "line", None))

    def test_severity_is_info_because_ffuf_reports_discovery_not_weakness(self):
        """
        Discovery is not the same as a weakness: ffuf reports what it found, not what is wrong.

        A 200 on /index.html is not a weakness while an exposed /.git is, and the tool cannot tell
        them apart - so everything imports at Info, as DefectDojo does for an open port from nmap.
        """
        findings = self.parse("ffuf_many_vuln.json")
        self.assertEqual({"Info"}, {finding.severity for finding in findings})

    def test_many_vuln(self):
        findings = self.parse("ffuf_many_vuln.json")
        self.assertEqual(5, len(findings))
        self.assertEqual(
            [
                "HTTP 200: /index.html",
                "HTTP 200: /robots.txt",
                "HTTP 301: /.git",
                "HTTP 301: /admin",
                "HTTP 301: /backup",
            ],
            sorted(finding.title for finding in findings),
        )
        for finding in findings:
            self.assertEqual(1, len(finding.unsaved_endpoints))

    def test_the_command_line_is_kept_as_evidence(self):
        """
        The matcher and filter settings decide what counted as a hit.

        Without the command, a reader cannot tell whether a status was matched deliberately or by
        ffuf's defaults.
        """
        finding = self.parse("ffuf_one_vuln.json")[0]
        self.assertIn("**Command:** `ffuf -u http://wave3target/FUZZ", finding.description)

    def test_the_internal_request_hash_is_not_reported(self):
        """FFUFHASH identifies a request, not a finding, so it is not presented as a payload."""
        finding = self.parse("ffuf_one_vuln.json")[0]
        self.assertNotIn("FFUFHASH", finding.description)

    def test_a_custom_keyword_is_labelled(self):
        """A run using -w list:KEY reports that keyword instead of FUZZ."""
        report = io.StringIO(json.dumps({
            "commandline": "ffuf ...",
            "results": [{
                "input": {"FFUFHASH": "abc", "DIRS": "admin"},
                "status": 200,
                "url": "http://target.example.com/admin",
            }],
        }))
        finding = list(FfufParser().get_findings(report, Test()))[0]
        self.assertIn("**Payload (DIRS):** admin", finding.description)

    def test_result_without_a_status(self):
        report = io.StringIO(json.dumps({
            "results": [{"input": {"FUZZ": "x"}, "url": "http://target.example.com/x"}],
        }))
        finding = list(FfufParser().get_findings(report, Test()))[0]
        self.assertEqual("Discovered: /x", finding.title)

    def test_result_without_a_url(self):
        report = io.StringIO(json.dumps({"results": [{"input": {"FUZZ": "x"}, "status": 200}]}))
        finding = list(FfufParser().get_findings(report, Test()))[0]
        self.assertEqual("HTTP 200: /", finding.title)
        self.assertEqual([], finding.unsaved_endpoints)

    def test_absent_results_key(self):
        self.assertEqual([], list(FfufParser().get_findings(io.StringIO("{}"), Test())))

    def test_wrong_shape_is_rejected(self):
        with self.assertRaises(TypeError):
            list(FfufParser().get_findings(io.StringIO("[]"), Test()))
        with self.assertRaises(TypeError):
            list(FfufParser().get_findings(io.StringIO('{"results": ["x"]}'), Test()))
