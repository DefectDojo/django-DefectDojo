import io
import json

from dojo.models import Finding, Test
from dojo.tools.xygeni.parser import XygeniParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestXygeniParser(DojoTestCase):

    def _load(self, filename):
        return (get_unit_tests_scans_path("xygeni") / filename).open(encoding="utf-8")

    # ----- empty-report cases -----

    def test_sast_no_findings(self):
        with self._load("sast_no_findings.json") as testfile:
            findings = XygeniParser().get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_sca_no_findings(self):
        with self._load("sca_no_findings.json") as testfile:
            findings = XygeniParser().get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_secrets_no_findings(self):
        with self._load("secrets_no_findings.json") as testfile:
            findings = XygeniParser().get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    # ----- populated-report cases -----

    def test_sast_many_findings(self):
        with self._load("sast_many_findings.json") as testfile:
            findings = XygeniParser().get_findings(testfile, Test())

        self.assertGreater(len(findings), 100)
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)
            self.assertIsNotNone(finding.unique_id_from_tool)

        match = next(
            (f for f in findings if f.unique_id_from_tool == "nsXRi+PTLom/sG8m6weOXw"),
            None,
        )
        self.assertIsNotNone(match, "expected the deserialization SAST finding by uniqueHash")
        self.assertEqual("python.code_injection_deserialization", match.title)
        self.assertEqual("Critical", match.severity)
        self.assertEqual(502, match.cwe)
        self.assertEqual("dockerized_labs/insec_des_lab/main.py", match.file_path)
        self.assertEqual(36, match.line)
        # codeFlows[] populates the SAST source/sink fields
        self.assertEqual("dockerized_labs/insec_des_lab/main.py", match.sast_source_file_path)
        self.assertEqual(33, match.sast_source_line)
        self.assertEqual("serialized_data", match.sast_source_object)
        self.assertIn("Data flow", match.description)

    def test_sca_many_findings(self):
        with self._load("sca_many_findings.json") as testfile:
            findings = XygeniParser().get_findings(testfile, Test())

        self.assertGreater(len(findings), 0)
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertTrue(finding.static_finding)
            self.assertIsNotNone(finding.component_name)
            self.assertIsNotNone(finding.component_version)

        match = next(
            (
                f for f in findings
                if f.component_name == "cookie"
                and f.component_version == "0.5.0"
                and f.vuln_id_from_tool == "SCA.CVE-2024-47764"
            ),
            None,
        )
        self.assertIsNotNone(match, "expected the cookie@0.5.0 / CVE-2024-47764 SCA finding")
        self.assertEqual("CVE-2024-47764", match.title)
        self.assertEqual("CVE-2024-47764", match.cve)
        self.assertIn("CVE-2024-47764", match.unsaved_vulnerability_ids)
        self.assertIn("GHSA-pxg6-pf52-xh8x", match.unsaved_vulnerability_ids)
        self.assertIn("0.7.0", match.mitigation)
        # overallCvssScore = -1.0 in this fixture → must be dropped, not surfaced
        self.assertIsNone(match.cvssv3_score)

    def test_secrets_many_findings(self):
        with self._load("secrets_many_findings.json") as testfile:
            findings = XygeniParser().get_findings(testfile, Test())

        self.assertGreater(len(findings), 0)
        for finding in findings:
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertTrue(finding.static_finding)
            self.assertIsNotNone(finding.cwe)

        match = next(
            (f for f in findings if f.unique_id_from_tool == "LVAjuA4Z40VxktixjtztXg"),
            None,
        )
        self.assertIsNotNone(match, "expected the .ssh/id_rsa private-key secret finding")
        self.assertEqual("Critical", match.severity)
        self.assertEqual(".ssh/id_rsa", match.file_path)
        self.assertEqual(1, match.line)
        self.assertIn("private_key", match.title)
        self.assertIn("Rotate", match.mitigation)

    # ----- dispatch + error cases -----

    def test_dispatches_on_metadata_scan_type(self):
        report = {
            "metadata": {"scanType": "secrets", "format": "secrets-xygeni"},
            "secrets": [
                {
                    "type": "aws_access_key",
                    "detector": "aws-access-key",
                    "severity": "high",
                    "location": {"filepath": "config.ini", "beginLine": 12, "code": "key=AKIA****"},
                    "description": "AWS access key ID detected.",
                    "uniqueHash": "abc123",
                    "issueId": "SECRETS.aws-access-key.config.ini:12",
                    "tags": ["cwe:798"],
                },
            ],
        }
        findings = XygeniParser().get_findings(io.StringIO(json.dumps(report)), Test())
        self.assertEqual(1, len(findings))
        self.assertEqual("abc123", findings[0].unique_id_from_tool)
        self.assertEqual(798, findings[0].cwe)

    def test_raises_on_missing_scan_type(self):
        report = {"metadata": {}, "vulnerabilities": []}
        with self.assertRaises(ValueError):
            XygeniParser().get_findings(io.StringIO(json.dumps(report)), Test())

    def test_raises_on_unsupported_scan_type(self):
        report = {"metadata": {"scanType": "iac"}, "flaws": []}
        with self.assertRaises(ValueError):
            XygeniParser().get_findings(io.StringIO(json.dumps(report)), Test())

    # ----- scan-type registry -----

    def test_get_scan_types_returns_phase_one_kinds(self):
        scan_types = XygeniParser().get_scan_types()
        self.assertIn("Xygeni SAST Scan", scan_types)
        self.assertIn("Xygeni SCA Scan", scan_types)
        self.assertIn("Xygeni Secrets Scan", scan_types)
        self.assertEqual(3, len(scan_types))
