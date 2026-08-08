import io
import json

from dojo.models import Finding, Test
from dojo.tools.gitguardian.parser import GitGuardianParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestGitGuardianParser(DojoTestCase):
    def scan(self, filename):
        return get_unit_tests_scans_path("gitguardian") / filename

    def parse(self, filename):
        with self.scan(filename).open(encoding="utf-8") as file:
            return list(GitGuardianParser().get_findings(file, Test()))

    def by_uid(self, filename):
        return {f.unique_id_from_tool: f for f in self.parse(filename)}

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal ScanTypeName in the GitGuardian connector verbatim.

        Any drift and a customer who uploads an export and also syncs the API gets two
        un-deduplicated copies of every finding.
        """
        parser = GitGuardianParser()
        self.assertEqual(["GitGuardian - Connectors Import"], parser.get_scan_types())
        self.assertEqual(
            "GitGuardian - Connectors Import",
            parser.get_label_for_scan_types("GitGuardian - Connectors Import"),
        )

    def test_no_vuln(self):
        self.assertEqual(0, len(self.parse("gitguardian_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("gitguardian_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring toFinding in the connector's converter."""
        findings = self.parse("gitguardian_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("AWS IAM key exposed in generic-app", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("aws_iam", finding.vuln_id_from_tool)
        self.assertEqual("gitguardian-incident-5001", finding.unique_id_from_tool)
        self.assertEqual("https://dashboard.example.com/incidents/5001", finding.url)

        self.assertIn("GitGuardian detected an exposed **AWS IAM Key**.", finding.description)
        self.assertIn("**Detector:** family api_key, category cloud_provider", finding.description)
        self.assertIn("**Occurrences:** 3", finding.description)
        self.assertIn("**Details:** https://dashboard.example.com/incidents/5001",
                      finding.description)

    def test_a_confirmed_live_credential_is_marked_verified(self):
        """
        GitGuardian actively checks whether a discovered credential still authenticates.

        The connector marks only "valid" as verified: an unchecked credential is not evidence either
        way, and marking it verified would overstate what GitGuardian knows.
        """
        finding = self.parse("gitguardian_one_vuln.json")[0]
        self.assertTrue(finding.verified)
        self.assertIn("still live and actively exploitable", finding.description)

    def test_an_invalid_or_unchecked_credential_is_not_marked_verified(self):
        findings = self.by_uid("gitguardian_many_vuln.json")
        for uid in ("gitguardian-incident-5002", "gitguardian-incident-5003",
                    "gitguardian-incident-5004"):
            self.assertFalse(findings[uid].verified, uid)

    def test_the_validity_verdict_is_spelled_out(self):
        """
        The converter's validityNarrative(): the three unverified states share one narrative.

        A bare enum value such as "no_checker" tells a triager nothing.
        """
        findings = self.by_uid("gitguardian_many_vuln.json")
        self.assertIn("no longer authenticates",
                      findings["gitguardian-incident-5002"].description)
        self.assertIn("could not automatically check",
                      findings["gitguardian-incident-5003"].description)
        # An unrecognised validity contributes no narrative line at all.
        self.assertNotIn("**Validity:**", findings["gitguardian-incident-5004"].description)

    def test_all_three_unverified_states_share_the_narrative(self):
        parser = GitGuardianParser()
        for validity in ("no_checker", "not_checked", "failed_to_check"):
            finding = parser.build_finding(
                {"id": 1, "validity": validity, "detector": {}}, Test(),
            )
            self.assertIn("could not automatically check", finding.description, validity)

    def test_a_revoked_secret_is_called_out(self):
        finding = self.by_uid("gitguardian_many_vuln.json")["gitguardian-incident-5002"]
        self.assertIn("**Revoked:** the secret has been marked revoked in GitGuardian.",
                      finding.description)

    def test_an_incident_with_no_name_is_titled_from_the_detector(self):
        finding = self.by_uid("gitguardian_many_vuln.json")["gitguardian-incident-5002"]
        self.assertEqual("Generic API Key detected", finding.title)

    def test_an_incident_with_no_detector_display_name_falls_back_to_secret(self):
        """The converter's own fallbacks: "Secret detected", and "secret" in the description."""
        finding = self.by_uid("gitguardian_many_vuln.json")["gitguardian-incident-5003"]
        self.assertEqual("Secret detected", finding.title)
        self.assertIn("GitGuardian detected an exposed **secret**.", finding.description)
        # An empty family and category contribute no detector line.
        self.assertNotIn("**Detector:**", finding.description)
        # A zero occurrence count is omitted rather than printed as zero.
        self.assertNotIn("**Occurrences:**", finding.description)

    def test_an_incident_with_no_url_leaves_the_url_unset(self):
        finding = self.by_uid("gitguardian_many_vuln.json")["gitguardian-incident-5003"]
        self.assertIsNone(finding.url)
        self.assertNotIn("**Details:**", finding.description)

    def test_an_unrecognised_severity_is_info(self):
        finding = self.by_uid("gitguardian_many_vuln.json")["gitguardian-incident-5004"]
        self.assertEqual("Info", finding.severity)

    def test_every_finding_carries_the_revoke_and_purge_mitigation(self):
        """
        Every incident here is an exposed credential, so the remediation is always the same.

        The connector hardcodes it, and leaving it off would ship findings with no guidance.
        """
        for finding in self.parse("gitguardian_many_vuln.json"):
            self.assertIn("Revoke and rotate the exposed credential", finding.mitigation)
            self.assertIn("purge it from version-control history", finding.mitigation)

    def test_no_secret_value_is_imported(self):
        """
        GitGuardian's incidents endpoint does not return the matched secret.

        Asserted so a future change that starts pulling occurrences cannot quietly begin copying
        credentials into the database.
        """
        raw = self.scan("gitguardian_many_vuln.json").read_text(encoding="utf-8")
        self.assertNotIn("secret_value", raw)
        for finding in self.parse("gitguardian_many_vuln.json"):
            self.assertNotIn("secret_value", finding.description)

    def test_an_envelope_is_accepted(self):
        incident = {"id": 1, "severity": "low", "detector": {"name": "d", "display_name": "D"}}
        for payload in ({"incidents": [incident]}, {"results": [incident]}, {"data": [incident]}):
            report = io.StringIO(json.dumps(payload))
            self.assertEqual(
                1, len(list(GitGuardianParser().get_findings(report, Test()))), payload,
            )

    def test_a_repeated_incident_id_collapses(self):
        incident = {"id": 1, "severity": "low", "detector": {"name": "d"}}
        report = io.StringIO(json.dumps([incident, incident]))
        self.assertEqual(1, len(list(GitGuardianParser().get_findings(report, Test()))))

    def test_an_unexpected_shape_is_rejected_with_a_clear_message(self):
        with self.assertRaises(TypeError) as raised:
            list(GitGuardianParser().get_findings(io.StringIO('"nope"'), Test()))
        self.assertIn("incidents", str(raised.exception))
