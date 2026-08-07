import io

from dojo.models import Finding, Test
from dojo.tools.masscan.parser import MasscanParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestMasscanParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("masscan") / filename).open(encoding="utf-8") as file:
            return list(MasscanParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = MasscanParser()
        self.assertEqual(["Masscan Scan"], parser.get_scan_types())
        self.assertEqual("Masscan Scan", parser.get_label_for_scan_types("Masscan Scan"))
        self.assertIn("masscan -oJ", parser.get_description_for_scan_types("Masscan Scan"))

    def test_no_vuln(self):
        """
        Masscan writes an EMPTY file when it finds nothing, not an empty JSON array.

        The fixture is a real zero-byte file from scanning a closed port, and it has to parse rather
        than raise, because that is the ordinary result of a scan that finds nothing.
        """
        self.assertEqual(0, (get_unit_tests_scans_path("masscan") / "masscan_no_vuln.json").stat().st_size)
        self.assertEqual(0, len(self.parse("masscan_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("masscan_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `masscan -oJ` run against a local container."""
        findings = self.parse("masscan_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Open port: 80/tcp on 172.29.0.3", finding.title)
        self.assertEqual("Info", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertTrue(finding.dynamic_finding)
        self.assertFalse(finding.static_finding)
        self.assertEqual(1, len(self.get_unsaved_locations(finding)))

        self.assertIn("**Host:** 172.29.0.3", finding.description)
        self.assertIn("**Port:** 80/tcp", finding.description)
        self.assertIn("**Reason:** syn-ack", finding.description)
        self.assertIn("**TTL:** 64", finding.description)

    def test_many_vuln(self):
        findings = self.parse("masscan_many_vuln.json")
        self.assertEqual(4, len(findings))
        self.assertEqual(
            [80, 3000, 8080, 8443],
            sorted(int(finding.title.split(": ")[1].split("/")[0]) for finding in findings),
        )
        for finding in findings:
            self.assertEqual(1, len(self.get_unsaved_locations(finding)))

    def test_severity_is_info_because_an_open_port_is_an_observation(self):
        """
        Whether a port should be open is a question about the host, not something masscan answers.

        DefectDojo already treats nmap's open ports as Info, and this follows that.
        """
        findings = self.parse("masscan_many_vuln.json")
        self.assertEqual({"Info"}, {finding.severity for finding in findings})

    def test_the_endpoint_is_host_and_port_not_a_url(self):
        """
        An open port has no scheme, so the endpoint is built as //host:port.

        A bare host would be parsed as a URL path instead of a hostname.
        """
        finding = self.parse("masscan_one_vuln.json")[0]
        location = self.get_unsaved_locations(finding)[0]
        self.assertEqual("172.29.0.3", location.host)
        self.assertEqual(80, location.port)

    def test_a_closed_port_is_not_a_finding(self):
        """Masscan reports a closed port when it gets a RST, which is the opposite of a finding."""
        report = io.StringIO(
            '[\n{"ip":"203.0.113.10","ports":[{"port":80,"proto":"tcp","status":"closed",'
            '"reason":"rst","ttl":64}]}\n]',
        )
        self.assertEqual([], list(MasscanParser().get_findings(report, Test())))

    def test_a_host_reporting_several_ports_in_one_record(self):
        """Masscan normally writes one port per record, but the ports field is a list."""
        report = io.StringIO(
            '[\n{"ip":"203.0.113.10","ports":['
            '{"port":80,"proto":"tcp","status":"open"},'
            '{"port":443,"proto":"tcp","status":"open"}]}\n]',
        )
        findings = list(MasscanParser().get_findings(report, Test()))
        self.assertEqual(2, len(findings))
        self.assertEqual(
            ["Open port: 443/tcp on 203.0.113.10", "Open port: 80/tcp on 203.0.113.10"],
            sorted(finding.title for finding in findings),
        )

    def test_udp_is_not_reported_as_tcp(self):
        report = io.StringIO('[{"ip":"203.0.113.10","ports":[{"port":53,"proto":"udp","status":"open"}]}]')
        finding = list(MasscanParser().get_findings(report, Test()))[0]
        self.assertEqual("Open port: 53/udp on 203.0.113.10", finding.title)

    def test_a_repeated_port_collapses(self):
        """A retransmitted probe can be answered twice, so the same open port can appear twice."""
        report = io.StringIO(
            '[\n{"ip":"203.0.113.10","ports":[{"port":80,"proto":"tcp","status":"open"}]}\n'
            ',\n{"ip":"203.0.113.10","ports":[{"port":80,"proto":"tcp","status":"open"}]}\n]',
        )
        self.assertEqual(1, len(list(MasscanParser().get_findings(report, Test()))))

    def test_the_same_port_on_two_hosts_stays_two_findings(self):
        report = io.StringIO(
            '[\n{"ip":"203.0.113.10","ports":[{"port":80,"proto":"tcp","status":"open"}]}\n'
            ',\n{"ip":"203.0.113.11","ports":[{"port":80,"proto":"tcp","status":"open"}]}\n]',
        )
        self.assertEqual(2, len(list(MasscanParser().get_findings(report, Test()))))

    def test_a_trailing_comma_is_tolerated(self):
        """
        Some masscan versions leave a trailing comma before the closing bracket.

        That is not valid JSON, but the file is otherwise fine and the ports in it are real, so it
        is repaired rather than rejected.
        """
        report = io.StringIO(
            '[\n{"ip":"203.0.113.10","ports":[{"port":80,"proto":"tcp","status":"open"}]}\n,\n]',
        )
        findings = list(MasscanParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("Open port: 80/tcp on 203.0.113.10", findings[0].title)

    def test_bytes_input(self):
        report = io.BytesIO(b'[{"ip":"203.0.113.10","ports":[{"port":80,"proto":"tcp","status":"open"}]}]')
        self.assertEqual(1, len(list(MasscanParser().get_findings(report, Test()))))

    def test_a_json_object_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(MasscanParser().get_findings(io.StringIO('{"ip":"1.2.3.4"}'), Test()))
        self.assertIn("array", str(raised.exception))

    def test_a_non_object_array_entry_is_rejected(self):
        with self.assertRaises(TypeError):
            list(MasscanParser().get_findings(io.StringIO("[42]"), Test()))

    def test_text_that_is_not_json_is_rejected(self):
        with self.assertRaises(ValueError) as raised:
            list(MasscanParser().get_findings(io.StringIO("not json at all"), Test()))
        self.assertIn("JSON", str(raised.exception))
