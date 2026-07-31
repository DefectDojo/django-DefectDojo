import io

from dojo.models import Finding, Test
from dojo.tools.naabu.parser import NaabuParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestNaabuParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("naabu") / filename).open(encoding="utf-8") as file:
            return list(NaabuParser().get_findings(file, Test()))

    def test_scan_type_metadata(self):
        parser = NaabuParser()
        self.assertEqual(["Naabu Scan"], parser.get_scan_types())
        self.assertEqual("Naabu Scan", parser.get_label_for_scan_types("Naabu Scan"))
        self.assertIn("JSON Lines", parser.get_description_for_scan_types("Naabu Scan"))

    def test_no_vuln(self):
        """
        Naabu prints nothing when no port is open, so a clean capture is an empty file.

        An empty file has to parse rather than raise, because that is the ordinary result of scanning
        a host with the ports in question closed.
        """
        self.assertEqual(0, len(self.parse("naabu_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("naabu_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, from a real `naabu -json` run against a local container."""
        findings = self.parse("naabu_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Open port: 80/tcp on 172.29.0.3", finding.title)
        self.assertEqual("Info", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertTrue(finding.dynamic_finding)
        self.assertFalse(finding.static_finding)
        self.assertEqual(1, len(finding.unsaved_endpoints))

        self.assertIn("**Port:** 80/tcp", finding.description)
        self.assertIn("**TLS:** no", finding.description)

    def test_duplicate_lines_collapse_to_one_finding(self):
        """
        Naabu reports the same open port once per scan pass.

        The one-port fixture has TWO lines for port 80 and the many-port fixture has eight lines for
        four ports, so without keying on host, port and protocol every open port would import twice.
        """
        with (get_unit_tests_scans_path("naabu") / "naabu_one_vuln.json").open(
            encoding="utf-8",
        ) as file:
            self.assertEqual(2, len([line for line in file if line.strip()]))
        self.assertEqual(1, len(self.parse("naabu_one_vuln.json")))

        with (get_unit_tests_scans_path("naabu") / "naabu_many_vuln.json").open(
            encoding="utf-8",
        ) as file:
            self.assertEqual(8, len([line for line in file if line.strip()]))
        self.assertEqual(4, len(self.parse("naabu_many_vuln.json")))

    def test_many_vuln_ports(self):
        findings = self.parse("naabu_many_vuln.json")
        self.assertEqual([80, 3000, 8080, 8443], sorted(
            int(finding.title.split(": ")[1].split("/")[0]) for finding in findings
        ))
        for finding in findings:
            self.assertEqual("Info", finding.severity)
            self.assertEqual(1, len(finding.unsaved_endpoints))

    def test_severity_is_info_because_an_open_port_is_an_observation(self):
        """
        Whether a port should be open is a question about the host, not something naabu can answer.

        DefectDojo already treats nmap's open ports as Info, and this follows that.
        """
        findings = self.parse("naabu_many_vuln.json")
        self.assertEqual({"Info"}, {finding.severity for finding in findings})

    def test_the_endpoint_is_host_and_port_not_a_url(self):
        """
        An open port has no scheme, so the endpoint is built as //host:port.

        A bare host would be parsed as a URL path instead of a hostname.
        """
        finding = self.parse("naabu_one_vuln.json")[0]
        self.assertEqual("//172.29.0.3:80", finding.unsaved_endpoints[0].uri)

    def test_a_resolved_hostname_reports_both_names(self):
        """Scanning a hostname makes naabu report the name and the address it resolved to."""
        report = io.StringIO(
            '{"host":"target.example.com","ip":"203.0.113.10","port":443,'
            '"protocol":"tcp","tls":true}\n',
        )
        finding = list(NaabuParser().get_findings(report, Test()))[0]
        self.assertEqual("Open port: 443/tcp on target.example.com", finding.title)
        self.assertIn("**Host:** target.example.com", finding.description)
        self.assertIn("**Address:** 203.0.113.10", finding.description)
        self.assertIn("**TLS:** yes", finding.description)
        self.assertEqual("//target.example.com:443", finding.unsaved_endpoints[0].uri)

    def test_udp_is_not_reported_as_tcp(self):
        report = io.StringIO('{"ip":"203.0.113.10","port":53,"protocol":"udp"}\n')
        finding = list(NaabuParser().get_findings(report, Test()))[0]
        self.assertEqual("Open port: 53/udp on 203.0.113.10", finding.title)

    def test_the_same_port_on_two_hosts_stays_two_findings(self):
        report = io.StringIO(
            '{"ip":"203.0.113.10","port":80,"protocol":"tcp"}\n'
            '{"ip":"203.0.113.11","port":80,"protocol":"tcp"}\n',
        )
        self.assertEqual(2, len(list(NaabuParser().get_findings(report, Test()))))

    def test_blank_lines_are_ignored(self):
        report = io.StringIO('\n{"ip":"203.0.113.10","port":80,"protocol":"tcp"}\n\n')
        self.assertEqual(1, len(list(NaabuParser().get_findings(report, Test()))))

    def test_bytes_input(self):
        report = io.BytesIO(b'{"ip":"203.0.113.10","port":80,"protocol":"tcp"}\n')
        self.assertEqual(1, len(list(NaabuParser().get_findings(report, Test()))))

    def test_a_json_array_is_rejected_with_a_clear_message(self):
        """
        Naabu writes JSON Lines, not a JSON array, and the two are easy to confuse.

        Saying so beats a bare JSONDecodeError.
        """
        with self.assertRaises(TypeError) as raised:
            list(NaabuParser().get_findings(io.StringIO('[{"ip":"1.2.3.4","port":80}]'), Test()))
        self.assertIn("JSON Lines", str(raised.exception))

        # A line that is not JSON at all takes the other path, and says the same thing.
        with self.assertRaises(ValueError) as decode_failure:
            list(NaabuParser().get_findings(io.StringIO("not json at all"), Test()))
        self.assertIn("JSON Lines", str(decode_failure.exception))

    def test_a_non_object_line_is_rejected(self):
        with self.assertRaises(TypeError):
            list(NaabuParser().get_findings(io.StringIO("42\n"), Test()))
