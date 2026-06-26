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
            (
                f for f in findings
                if f.unique_id_from_tool == "SAS.injection.python.code_injection_deserialization.dockerized_labs/insec_des_lab/main.py.36"
            ),
            None,
        )
        self.assertIsNotNone(match, "expected the deserialization SAST finding by issueId")
        # uniqueHash is kept as the vuln id; the per-occurrence issueId drives dedup
        self.assertEqual("nsXRi+PTLom/sG8m6weOXw", match.vuln_id_from_tool)
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

    def test_sast_repeated_detector_in_same_file_stays_distinct(self):
        # One detector flagging the same pattern at several lines shares a uniqueHash but
        # carries a distinct issueId per line. Each occurrence must remain its own Finding.
        with self._load("sast_many_findings.json") as testfile:
            findings = XygeniParser().get_findings(testfile, Test())

        occurrences = [
            f for f in findings
            if f.vuln_id_from_tool == "VsqoC9U6q8EYG0QZ5UqxXw"  # forms_without_csrf_protection, 4 lines
        ]
        self.assertEqual(4, len(occurrences), "all occurrences of the repeated detector must be kept")
        unique_ids = {f.unique_id_from_tool for f in occurrences}
        self.assertEqual(4, len(unique_ids), "each occurrence needs a distinct unique_id_from_tool")

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
            (f for f in findings if f.unique_id_from_tool == "SEC.private_key.private_key..ssh/id_rsa.1"),
            None,
        )
        self.assertIsNotNone(match, "expected the .ssh/id_rsa private-key secret finding")
        # uniqueHash is kept as the vuln id; the per-occurrence issueId drives dedup
        self.assertEqual("LVAjuA4Z40VxktixjtztXg", match.vuln_id_from_tool)
        self.assertEqual("Critical", match.severity)
        self.assertEqual(".ssh/id_rsa", match.file_path)
        self.assertEqual(1, match.line)
        self.assertIn("private_key", match.title)
        self.assertIn("Rotate", match.mitigation)

    def test_secrets_repeated_in_same_file_stay_distinct(self):
        # A secret value repeated in one file shares a uniqueHash across occurrences but
        # carries a distinct issueId per line. The parser must surface each occurrence as
        # its own Finding (distinct unique_id_from_tool) so dedup does not collapse them.
        with self._load("secrets_many_findings.json") as testfile:
            findings = XygeniParser().get_findings(testfile, Test())

        occurrences = [
            f for f in findings
            if f.vuln_id_from_tool == "1yvAV2ndtW4yYG+TJQhhXg"  # .docker/.dockercfg, lines 9 and 29
        ]
        self.assertEqual(2, len(occurrences), "both occurrences of the repeated secret must be kept")
        unique_ids = {f.unique_id_from_tool for f in occurrences}
        self.assertEqual(2, len(unique_ids), "each occurrence needs a distinct unique_id_from_tool")
        self.assertEqual({9, 29}, {f.line for f in occurrences})

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
        self.assertEqual("SECRETS.aws-access-key.config.ini:12", findings[0].unique_id_from_tool)
        self.assertEqual("abc123", findings[0].vuln_id_from_tool)
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
