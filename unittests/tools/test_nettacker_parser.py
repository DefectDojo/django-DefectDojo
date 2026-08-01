import io
import json

from dojo.models import Finding, Test
from dojo.tools.nettacker.parser import NettackerParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestNettackerParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("nettacker") / filename).open(encoding="utf-8") as file:
            return list(NettackerParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = NettackerParser()
        self.assertEqual(["Nettacker Scan"], parser.get_scan_types())
        self.assertEqual("Nettacker Scan", parser.get_label_for_scan_types("Nettacker Scan"))
        self.assertIn("Nettacker", parser.get_description_for_scan_types("Nettacker Scan"))

    def test_no_vuln(self):
        """
        Nettacker writes an EMPTY file when no module produces an event.

        The fixture is that real zero-byte file, from a port scan of a closed port, and it has to
        parse rather than raise.
        """
        path = get_unit_tests_scans_path("nettacker") / "nettacker_no_vuln.json"
        self.assertEqual(0, path.stat().st_size)
        self.assertEqual(0, len(self.parse("nettacker_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("nettacker_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real Nettacker 0.4.0 run against a local container."""
        findings = self.parse("nettacker_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("port_scan: wave3target:80", finding.title)
        self.assertEqual("Info", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("port_scan", finding.vuln_id_from_tool)
        self.assertTrue(finding.dynamic_finding)
        self.assertFalse(finding.static_finding)

        self.assertIn("**Module:** port_scan", finding.description)
        self.assertIn("**Target:** wave3target", finding.description)
        self.assertIn("**Port:** 80", finding.description)
        self.assertIn("**Event:** host: wave3target", finding.description)

        self.assertEqual(1, len(self.get_unsaved_locations(finding)))
        location = self.get_unsaved_locations(finding)[0]
        self.assertEqual("wave3target", location.host)
        self.assertEqual(80, location.port)

    def test_many_vuln(self):
        findings = self.parse("nettacker_many_vuln.json")
        self.assertEqual(2, len(findings))
        self.assertEqual(
            ["port_scan: wave3ports:80", "port_scan: wave3ports:8080"],
            sorted(finding.title for finding in findings),
        )

    def test_a_scan_module_is_info_because_it_reports_what_exists(self):
        """
        Nettacker's report carries no severity field at all, so severity comes from the module.

        A scan module reports that a port answers or a path is served, which is an observation about
        the target rather than a weakness.
        """
        findings = self.parse("nettacker_many_vuln.json")
        self.assertEqual({"Info"}, {finding.severity for finding in findings})
        for finding in findings:
            # Finding.__init__ sets this to None, so a module naming no CVE leaves it None.
            self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_a_vulnerability_module_is_medium_and_carries_its_cve(self):
        """
        A module whose name ends in _vuln is a vulnerability check, and the CVE is in that name.

        The report does not repeat the CVE as a field, so the module name is the only place it can
        come from. This event is constructed rather than captured: the module name is real, taken
        from Nettacker's own module list, but no locally hosted target is vulnerable to it, so there
        was no way to make the check fire against something we host.
        """
        report = io.StringIO(json.dumps([{
            "scan_id": "aaaabbbbccccdddd",
            "target": "target.example.com",
            "module_name": "apache_cve_2021_41773_vuln",
            "date": "2026-07-31 19:04:10.096337",
            "port": 443,
            "event": "host: target.example.com method: http_get_request port: 443",
        }]))
        findings = list(NettackerParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual(
            "apache_cve_2021_41773_vuln fired against target.example.com:443",
            finding.title,
        )
        self.assertEqual("Medium", finding.severity)
        self.assertEqual(["CVE-2021-41773"], finding.unsaved_vulnerability_ids)
        self.assertEqual("apache_cve_2021_41773_vuln", finding.vuln_id_from_tool)

    def test_a_vulnerability_module_with_no_cve_in_its_name(self):
        """Not every _vuln module names a CVE, and one without should still be a finding."""
        report = io.StringIO(json.dumps([{
            "target": "target.example.com",
            "module_name": "weak_signature_algorithm_vuln",
            "port": 443,
        }]))
        finding = list(NettackerParser().get_findings(report, Test()))[0]
        self.assertEqual("Medium", finding.severity)
        # Finding.__init__ sets this to None, so a module naming no CVE leaves it None.
        self.assertIsNone(finding.unsaved_vulnerability_ids)

    def test_an_event_with_no_port_still_gets_an_endpoint(self):
        report = io.StringIO(json.dumps([{
            "target": "target.example.com",
            "module_name": "subdomain_scan",
        }]))
        finding = list(NettackerParser().get_findings(report, Test()))[0]
        self.assertEqual("subdomain_scan: target.example.com", finding.title)
        location = self.get_unsaved_locations(finding)[0]
        self.assertEqual("target.example.com", location.host)
        self.assertIsNone(location.port)
        self.assertNotIn("**Port:**", finding.description)

    def test_the_scan_id_and_date_are_not_in_the_description(self):
        """
        Both change on every run, so hashing them in would reimport every event on a rescan.

        The fixtures carry a real scan_id and date, so this is checked against real output.
        """
        content = (get_unit_tests_scans_path("nettacker") / "nettacker_many_vuln.json").read_text(
            encoding="utf-8",
        )
        self.assertIn("scan_id", content)
        self.assertIn("2026-07-31", content)

        for finding in self.parse("nettacker_many_vuln.json"):
            self.assertNotIn("scan_id", finding.description)
            self.assertNotIn("2026-07-31", finding.description)

    def test_a_repeated_event_collapses(self):
        """A module can report the same target and port more than once in a scan."""
        report = io.StringIO(json.dumps([
            {"target": "target.example.com", "module_name": "port_scan", "port": 80,
             "scan_id": "first", "date": "2026-07-31 19:04:10.000000"},
            {"target": "target.example.com", "module_name": "port_scan", "port": 80,
             "scan_id": "second", "date": "2026-07-31 19:05:11.000000"},
        ]))
        self.assertEqual(1, len(list(NettackerParser().get_findings(report, Test()))))

    def test_two_ports_on_one_target_stay_two_findings(self):
        report = io.StringIO(json.dumps([
            {"target": "target.example.com", "module_name": "port_scan", "port": 80},
            {"target": "target.example.com", "module_name": "port_scan", "port": 443},
        ]))
        self.assertEqual(2, len(list(NettackerParser().get_findings(report, Test()))))

    def test_two_modules_on_one_port_stay_two_findings(self):
        report = io.StringIO(json.dumps([
            {"target": "target.example.com", "module_name": "port_scan", "port": 80},
            {"target": "target.example.com", "module_name": "admin_scan", "port": 80},
        ]))
        self.assertEqual(2, len(list(NettackerParser().get_findings(report, Test()))))

    def test_bytes_input(self):
        report = io.BytesIO(
            b'[{"target":"target.example.com","module_name":"port_scan","port":80}]',
        )
        self.assertEqual(1, len(list(NettackerParser().get_findings(report, Test()))))

    def test_a_json_object_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(NettackerParser().get_findings(io.StringIO('{"target":"x"}'), Test()))
        self.assertIn("array of events", str(raised.exception))

    def test_a_non_object_event_is_rejected(self):
        with self.assertRaises(TypeError):
            list(NettackerParser().get_findings(io.StringIO("[42]"), Test()))

    def test_text_that_is_not_json_is_rejected(self):
        with self.assertRaises(ValueError):
            list(NettackerParser().get_findings(io.StringIO("not json at all"), Test()))
