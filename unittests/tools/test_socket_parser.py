import io
import json

from dojo.models import Finding, Test
from dojo.tools.socket.parser import SocketParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSocketParser(DojoTestCase):
    def parse(self, filename):
        with (get_unit_tests_scans_path("socket") / filename).open(encoding="utf-8") as file:
            return list(SocketParser().get_findings(file, Test()))

    def test_scan_type_matches_the_connector_exactly(self):
        """
        The scan type must equal the Socket connector's ScanType() verbatim.

        If it drifts, a customer who both uploads an export and syncs the API gets two
        un-deduplicated copies of every finding, because the two land in different test types.
        """
        parser = SocketParser()
        self.assertEqual(["Socket - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "Socket - Connectors Import",
            parser.get_label_for_scan_types("Socket - Connectors Import"),
        )

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("socket_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("socket_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring AlertToFinding in the connector's converter."""
        findings = self.parse("socket_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        # converter: fmt.Sprintf("%s in %s", alert.Type, component)
        self.assertEqual("malware in @example-scope/utils", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        # converter: namespace + "/" + name
        self.assertEqual("@example-scope/utils", finding.component_name)
        self.assertEqual("0.2.1", finding.component_version)
        # converter: UniqueIDFromTool = alert.Key
        self.assertEqual("alert-1", finding.unique_id_from_tool)
        self.assertEqual("package.json", finding.file_path)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)

        self.assertIn("**Socket alert:** malware", finding.description)
        self.assertIn("**Category:** supplyChainRisk", finding.description)
        self.assertIn("**Package:** pkg:npm/@example-scope/utils@0.2.1", finding.description)
        self.assertIn("**Ecosystem:** npm", finding.description)
        # The converter renders the free-form props as sorted key/value lines.
        self.assertIn("**confidence:** high", finding.description)
        self.assertIn("**note:** obfuscated install script", finding.description)

    def test_tags_match_the_converter(self):
        finding = self.parse("socket_one_vuln.json")[0]
        self.assertEqual(
            [
                "socket:malware",
                "category:supplyChainRisk",
                "ecosystem:npm",
                "pkg:npm/@example-scope/utils@0.2.1",
            ],
            finding.unsaved_tags,
        )

    def test_many_vuln(self):
        """One artifact can carry several alerts, and each alert is its own finding."""
        findings = self.parse("socket_many_vuln.json")
        self.assertEqual(5, len(findings))
        self.assertEqual(
            {"@example-scope/utils", "requests", "github.com/example/widget"},
            {f.component_name for f in findings},
        )

    def test_the_severity_ladder_is_the_connectors(self):
        """
        Socket grades alerts low | middle | high | critical - "middle", not "medium".

        The connector maps anything it does not recognise to Info, so this does too. Guessing
        "medium" here would silently downgrade every middle-severity alert to Info.
        """
        findings = {f.unique_id_from_tool: f.severity for f in self.parse("socket_many_vuln.json")}
        self.assertEqual("Critical", findings["alert-1"])
        self.assertEqual("High", findings["alert-2"])
        self.assertEqual("Medium", findings["alert-3"])   # severity "middle"
        self.assertEqual("Low", findings["alert-4"])
        self.assertEqual("Info", findings["alert-5"])     # severity "not-a-level"

    def test_an_artifact_with_no_namespace_uses_the_bare_name(self):
        finding = next(
            f for f in self.parse("socket_many_vuln.json") if f.unique_id_from_tool == "alert-2"
        )
        self.assertEqual("requests", finding.component_name)
        self.assertIn("**Package:** pkg:pypi/requests@2.0.0", finding.description)

    def test_an_alert_with_no_file_leaves_file_path_unset(self):
        finding = next(
            f for f in self.parse("socket_many_vuln.json") if f.unique_id_from_tool == "alert-3"
        )
        self.assertIsNone(finding.file_path)

    def test_a_bare_artifact_array_is_accepted(self):
        """What people save varies; a plain JSON array of artifacts is the commonest form."""
        report = io.StringIO(json.dumps([{
            "type": "npm", "name": "x", "version": "1.0.0",
            "alerts": [{"key": "k", "type": "cve", "severity": "high"}],
        }]))
        findings = list(SocketParser().get_findings(report, Test()))
        self.assertEqual(1, len(findings))
        self.assertEqual("cve in x", findings[0].title)

    def test_a_results_envelope_is_accepted(self):
        report = io.StringIO(json.dumps({"results": [{
            "type": "npm", "name": "x", "version": "1.0.0",
            "alerts": [{"key": "k", "type": "cve", "severity": "low"}],
        }]}))
        self.assertEqual(1, len(list(SocketParser().get_findings(report, Test()))))

    def test_a_repeated_alert_key_collapses(self):
        """The connector's identity is the alert key, so the same key is the same finding."""
        alert = {"key": "same", "type": "cve", "severity": "high"}
        report = io.StringIO(json.dumps([
            {"type": "npm", "name": "x", "version": "1.0.0", "alerts": [alert]},
            {"type": "npm", "name": "x", "version": "1.0.0", "alerts": [alert]},
        ]))
        self.assertEqual(1, len(list(SocketParser().get_findings(report, Test()))))

    def test_a_package_url_needs_both_type_and_name(self):
        report = io.StringIO(json.dumps([{
            "name": "x", "version": "1.0.0",
            "alerts": [{"key": "k", "type": "cve", "severity": "low"}],
        }]))
        finding = list(SocketParser().get_findings(report, Test()))[0]
        self.assertNotIn("**Package:**", finding.description)
        self.assertEqual(["socket:cve"], finding.unsaved_tags)

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(SocketParser().get_findings(io.StringIO('"a string"'), Test()))
        self.assertIn("artifacts", str(raised.exception))
