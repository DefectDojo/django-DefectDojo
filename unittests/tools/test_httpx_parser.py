import io
import json

from dojo.models import Finding, Test
from dojo.tools.httpx.parser import HttpxParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestHttpxParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("httpx") / filename).open(encoding="utf-8") as file:
            return list(HttpxParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = HttpxParser()
        self.assertEqual(["httpx Scan"], parser.get_scan_types())
        self.assertEqual("httpx Scan", parser.get_label_for_scan_types("httpx Scan"))
        self.assertIn("JSON Lines", parser.get_description_for_scan_types("httpx Scan"))

    def test_no_vuln(self):
        """
        Httpx writes NOTHING for a target that does not answer.

        The fixture is that real zero-byte capture, from probing a closed port, and it has to parse
        rather than raise.
        """
        path = get_unit_tests_scans_path("httpx") / "httpx_no_vuln.json"
        self.assertEqual(0, path.stat().st_size)
        self.assertEqual(0, len(self.parse("httpx_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("httpx_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `httpx -json -tech-detect` run against a local container."""
        findings = self.parse("httpx_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("http://172.29.0.2/ (HTTP 200)", finding.title)
        self.assertEqual("Info", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertTrue(finding.dynamic_finding)
        self.assertFalse(finding.static_finding)

        self.assertIn("**URL:** http://172.29.0.2/", finding.description)
        self.assertIn("**Status:** 200", finding.description)
        self.assertIn("**Page title:** generic-app", finding.description)
        self.assertIn("**Server:** nginx/1.31.3", finding.description)
        # -tech-detect reports "Name:Version" where it could identify one.
        self.assertIn("**Technologies:** Nginx:1.31.3", finding.description)
        self.assertIn("**Method:** GET", finding.description)
        self.assertIn("**Resolved to:** 172.29.0.2", finding.description)

        self.assertEqual(1, len(self.get_unsaved_locations(finding)))
        location = self.get_unsaved_locations(finding)[0]
        self.assertEqual("172.29.0.2", location.host)
        self.assertEqual("http", location.protocol)

    def test_many_vuln(self):
        findings = self.parse("httpx_many_vuln.json")
        self.assertEqual(5, len(findings))
        self.assertEqual(
            [
                "http://172.29.0.2/ (HTTP 200)",
                "http://172.29.0.2/.git/config (HTTP 200)",
                "http://172.29.0.2/admin/ (HTTP 200)",
                "http://172.29.0.2/login.html (HTTP 200)",
                "http://172.29.0.2/robots.txt (HTTP 200)",
            ],
            sorted(finding.title for finding in findings),
        )

    def test_severity_is_info_because_httpx_reports_what_is_running(self):
        """
        Httpx says what answered and what it is running, not that anything is wrong.

        Whether a reachable /admin or a disclosed server version matters is a question about the
        application. This matches the WhatWeb parser, which fingerprints the same way.
        """
        findings = self.parse("httpx_many_vuln.json")
        self.assertEqual({"Info"}, {finding.severity for finding in findings})

    def test_every_finding_carries_the_probed_url_as_its_endpoint(self):
        """Httpx reports the full URL it probed, so the endpoint needs no reconstructing."""
        for finding in self.parse("httpx_many_vuln.json"):
            self.assertEqual(1, len(self.get_unsaved_locations(finding)))
            self.assertEqual("172.29.0.2", self.get_unsaved_locations(finding)[0].host)
            self.assertEqual("http", self.get_unsaved_locations(finding)[0].protocol)

    def test_a_page_with_no_title_still_imports(self):
        """robots.txt has no title; httpx omits the field rather than sending an empty one."""
        finding = next(
            f for f in self.parse("httpx_many_vuln.json") if "robots.txt" in f.title
        )
        self.assertNotIn("**Page title:**", finding.description)
        self.assertIn("**Status:** 200", finding.description)

    def test_the_timestamp_and_response_time_are_not_in_the_description(self):
        """
        Both change on every run of an unchanged target and say nothing about what was found.

        The fixtures carry a real timestamp and duration, so this is checked against real output.
        """
        content = (get_unit_tests_scans_path("httpx") / "httpx_many_vuln.json").read_text(
            encoding="utf-8",
        )
        self.assertIn('"timestamp"', content)
        self.assertIn('"time"', content)

        for finding in self.parse("httpx_many_vuln.json"):
            self.assertNotIn("2026-07-31", finding.description)
            self.assertNotIn("ms", finding.description.split("**Technologies:**")[0])

    def test_a_failed_probe_is_not_a_finding(self):
        """With -probe httpx reports what it could not reach; that is the absence of a result."""
        report = io.StringIO(
            json.dumps({"url": "http://target.example.com/", "input": "http://target.example.com/",
                        "failed": True}) + "\n"
            + json.dumps({"url": "http://target.example.com/up", "status_code": 200,
                          "failed": False}) + "\n",
        )
        findings = list(HttpxParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("http://target.example.com/up (HTTP 200)", findings[0].title)

    def test_a_redirect_target_is_kept(self):
        report = io.StringIO(json.dumps({
            "url": "http://target.example.com/old",
            "status_code": 301,
            "location": "https://target.example.com/new",
        }))
        finding = list(HttpxParser().get_findings(report, Test()))[0]
        self.assertEqual("http://target.example.com/old (HTTP 301)", finding.title)
        self.assertIn("**Redirects to:** https://target.example.com/new", finding.description)

    def test_a_record_with_no_status_falls_back_to_the_url_alone(self):
        report = io.StringIO(json.dumps({"url": "http://target.example.com/"}))
        finding = list(HttpxParser().get_findings(report, Test()))[0]
        self.assertEqual("http://target.example.com/", finding.title)

    def test_the_input_is_used_when_no_url_is_reported(self):
        report = io.StringIO(json.dumps({"input": "http://target.example.com/", "status_code": 200}))
        finding = list(HttpxParser().get_findings(report, Test()))[0]
        self.assertEqual("http://target.example.com/ (HTTP 200)", finding.title)

    def test_a_repeated_url_collapses(self):
        """The same URL can appear twice in a target list passed with -l."""
        line = json.dumps({"url": "http://target.example.com/", "status_code": 200})
        report = io.StringIO(line + "\n" + line + "\n")
        self.assertEqual(1, len(list(HttpxParser().get_findings(report, Test()))))

    def test_two_urls_on_one_host_stay_two_findings(self):
        report = io.StringIO(
            json.dumps({"url": "http://target.example.com/a", "status_code": 200}) + "\n"
            + json.dumps({"url": "http://target.example.com/b", "status_code": 404}) + "\n",
        )
        self.assertEqual(2, len(list(HttpxParser().get_findings(report, Test()))))

    def test_blank_lines_are_ignored(self):
        report = io.StringIO(
            "\n" + json.dumps({"url": "http://target.example.com/", "status_code": 200}) + "\n\n",
        )
        self.assertEqual(1, len(list(HttpxParser().get_findings(report, Test()))))

    def test_bytes_input(self):
        report = io.BytesIO(b'{"url":"http://target.example.com/","status_code":200}\n')
        self.assertEqual(1, len(list(HttpxParser().get_findings(report, Test()))))

    def test_a_json_array_is_rejected_with_a_clear_message(self):
        """
        Httpx writes JSON Lines, not a JSON array, and the two are easy to confuse.

        Saying so beats a bare JSONDecodeError.
        """
        with self.assertRaises(TypeError) as raised:
            list(HttpxParser().get_findings(io.StringIO('[{"url":"http://x/"}]'), Test()))
        self.assertIn("JSON Lines", str(raised.exception))

        with self.assertRaises(ValueError) as decode_failure:
            list(HttpxParser().get_findings(io.StringIO("not json at all"), Test()))
        self.assertIn("JSON Lines", str(decode_failure.exception))

    def test_empty_report(self):
        self.assertEqual([], list(HttpxParser().get_findings(io.StringIO(""), Test())))
