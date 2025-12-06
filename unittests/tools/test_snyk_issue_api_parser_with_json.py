

from dojo.models import Test
from dojo.tools.snyk_issue_api.parser import SnykIssueApiParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSnykIssueApiParserWithJson(DojoTestCase):
    def parse_json(self, filename):
        with (get_unit_tests_scans_path("snyk_issue_api") / filename).open(encoding="utf-8") as testfile:
            parser = SnykIssueApiParser()
            return parser.get_findings(testfile, Test())

    def test_parse_sca_single_finding(self):
        findings = self.parse_json("snyk_sca_scan_api_single_vuln.json")
        self.assertEqual(1, len(findings))

    def test_parse_sca_finding_count(self):
        findings = self.parse_json("snyk_sca_scan_api_many_vuln.json")
        self.assertEqual(5, len(findings))

    def test_parse_code_findings_count(self):
        findings = self.parse_json("snyk_code_scan_api_many_vuln.json")
        self.assertEqual(3, len(findings))

    def test_parse_code_finding_csrf_open(self):
        findings = self.parse_json("snyk_code_scan_api_many_vuln.json")

        finding = findings[0]
        # Basic identification
        self.assertEqual("3916a413-2fca-45c9-a1bf-a1373258fe69", finding.unique_id_from_tool)

        # attributes.classes -> CWE
        self.assertEqual(352, finding.cwe)

        # attributes.coordinates -> fix_available, file_path, line
        if hasattr(finding, "fix_available"):
            self.assertEqual(False, finding.fix_available)
        self.assertEqual("path/path/file.abc", finding.file_path)
        self.assertEqual(65, finding.line)

        # attributes.created_at -> date
        self.assertEqual("2024-12-13", finding.date)

        # attributes.description
        self.assertEqual("Cross-Site Request Forgery (CSRF)", finding.description)

        # attributes.effective_severity_level -> severity
        self.assertEqual("High", finding.severity)

        # attributes.ignored -> false_p, active, verified
        self.assertEqual(False, finding.false_p)

        # attributes.key -> vuln_id_from_tool
        self.assertEqual("9a29d87f-aa94-47eb-b46f-375b293a8631", finding.vuln_id_from_tool)

        # attributes.problems -> unsaved_vulnerability_ids, impact
        self.assertEqual(["9a29d87f-aa94-47eb-b46f-375b293a8631"], finding.unsaved_vulnerability_ids)
        self.assertIn("Source: SNYK", finding.impact)
        self.assertIn("Type: vulnerability", finding.impact)
        self.assertIn("Last Updated: 2025-04-13T04:13:03.151452Z", finding.impact)

        # attributes.risk -> severity_justification
        self.assertIn("Risk Score: 829", finding.severity_justification)

        # attributes.status -> active, verified, is_mitigated
        self.assertEqual(True, finding.active)
        self.assertEqual(False, finding.verified)
        self.assertEqual(False, finding.is_mitigated)

        # attributes.title
        self.assertEqual("Cross-Site Request Forgery (CSRF)", finding.title)

        # attributes.type -> static_finding, dynamic_finding
        self.assertEqual(True, finding.static_finding)
        self.assertEqual(False, finding.dynamic_finding)

        # CVSS data (not present in code findings)
        self.assertIsNone(finding.cvssv3)
        self.assertIsNone(finding.cvssv4)

    def test_parse_code_finding_xss_ignored(self):
        findings = self.parse_json("snyk_code_scan_api_many_vuln.json")

        # Ignored - Not Vulnerable, does not expire
        finding = findings[1]
        # Basic identification
        self.assertEqual("605a2477-69d4-4317-8649-1f7b92fa7c27", finding.unique_id_from_tool)

        # attributes.classes -> CWE
        self.assertEqual(79, finding.cwe)

        # attributes.coordinates -> fix_available
        if hasattr(finding, "fix_available"):
            self.assertEqual(False, finding.fix_available)

        # attributes.created_at -> date (not explicitly tested but should be same)

        # attributes.description
        self.assertEqual("Cross-site Scripting (XSS)", finding.description)

        # attributes.effective_severity_level -> severity
        self.assertEqual("Medium", finding.severity)

        # attributes.ignored -> false_p, out_of_scope
        self.assertEqual(True, finding.false_p)  # This one is ignored
        self.assertEqual(False, finding.out_of_scope)

        # attributes.key -> vuln_id_from_tool
        self.assertEqual("b25fb1d7-c99b-46fb-818b-e94971ee9db0", finding.vuln_id_from_tool)

        # attributes.problems -> impact
        self.assertIn("Source: SNYK", finding.impact)
        self.assertIn("Type: vulnerability", finding.impact)
        self.assertIn("Last Updated: 2025-05-10T01:45:25.464473Z", finding.impact)

        # attributes.status -> active
        self.assertEqual(False, finding.active)  # ignored issues are not active

        # attributes.title
        self.assertEqual("Cross-site Scripting (XSS)", finding.title)

    def test_parse_code_finding_hardcoded_password_temp_ignored(self):
        findings = self.parse_json("snyk_code_scan_api_many_vuln.json")

        # Ignored Temporary - expires
        finding = findings[2]
        # Basic identification
        self.assertEqual("922e2d65-d2ce-4a5c-818c-ab196ba834c3", finding.unique_id_from_tool)

        # attributes.classes -> CWE (multiple CWEs)
        self.assertEqual(259, finding.cwe)
        self.assertEqual("Additional CWEs: CWE-798", finding.references)  # Has multiple CWEs

        # attributes.coordinates -> fix_available
        if hasattr(finding, "fix_available"):
            self.assertEqual(False, finding.fix_available)

        # attributes.created_at -> date
        self.assertEqual("2024-12-13", finding.date)

        # attributes.description
        self.assertEqual("Use of Hardcoded Passwords", finding.description)

        # attributes.effective_severity_level -> severity
        self.assertEqual("Low", finding.severity)

        # attributes.ignored -> false_p
        self.assertEqual(False, finding.false_p)

        # attributes.key -> vuln_id_from_tool
        self.assertEqual("a8edd3ae-722f-4668-81da-478b46fdf961", finding.vuln_id_from_tool)

        # attributes.problems -> unsaved_vulnerability_ids, impact
        self.assertEqual(["a8edd3ae-722f-4668-81da-478b46fdf961"], finding.unsaved_vulnerability_ids)
        self.assertIn("Source: SNYK", finding.impact)
        self.assertIn("Type: vulnerability", finding.impact)
        self.assertIn("Last Updated: 2025-05-31T01:32:18.84232Z", finding.impact)

        # attributes.status -> active
        self.assertEqual(True, finding.active)

        # attributes.title
        self.assertEqual("Use of Hardcoded Passwords", finding.title)

    def test_parse_sca_findings_status_open(self):
        findings = self.parse_json("snyk_sca_scan_api_many_vuln.json")

        # 1 - Open issue - following JSON structure order
        finding = findings[0]
        # Basic identification
        self.assertEqual("1534153a-33bb-434a-a80e-64690166ee4a", finding.unique_id_from_tool)

        # attributes.classes -> CWE
        self.assertEqual(400, finding.cwe)

        # attributes.coordinates -> fix_available, component info, reachability
        self.assertEqual(True, finding.fix_available)
        self.assertIn("Reachable: No", finding.impact)  # Not reachable
        self.assertEqual("pillow", finding.component_name)
        self.assertEqual("9.5.0", finding.component_version)
        self.assertEqual("pillow", finding.file_path)

        # attributes.created_at -> date
        self.assertEqual("2025-09-11", finding.date)

        # attributes.effective_severity_level -> severity
        self.assertEqual("High", finding.severity)

        # attributes.exploit_details (empty sources in this case - no exploit info in impact)

        # attributes.ignored -> false_p, active, verified, out_of_scope
        self.assertEqual(False, finding.false_p)
        self.assertEqual(True, finding.active)    # Open issue
        self.assertEqual(False, finding.verified)  # Open issues might not be verified
        self.assertEqual(False, finding.out_of_scope)

        # attributes.key -> vuln_id_from_tool
        self.assertEqual("SNYK-PYTHON-PILLOW-6219984", finding.vuln_id_from_tool)

        # attributes.problems -> unsaved_vulnerability_ids, impact
        self.assertEqual(["SNYK-PYTHON-PILLOW-6219984"], finding.unsaved_vulnerability_ids)

        self.assertIn("Source: SNYK", finding.impact)
        self.assertIn("Type: vulnerability", finding.impact)
        self.assertIn("Package: pillow", finding.impact)
        self.assertIn("Version: 9.5.0", finding.impact)

        # attributes.risk -> severity_justification
        self.assertIn("Risk Score: 115", finding.severity_justification)
        self.assertIn("v1", finding.severity_justification)

        # attributes.severities -> CVSS data
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", finding.cvssv3)
        self.assertEqual(7.5, finding.cvssv3_score)
        self.assertIsNone(finding.cvssv4)
        self.assertIsNone(finding.cvssv4_score)

        # attributes.status -> active, verified, is_mitigated, risk_accepted
        self.assertEqual(False, finding.is_mitigated)
        self.assertEqual(False, finding.risk_accepted)

        # attributes.title
        self.assertEqual("Denial of Service (DoS)", finding.title)

        # attributes.type -> static_finding, dynamic_finding
        self.assertEqual(True, finding.static_finding)
        self.assertEqual(False, finding.dynamic_finding)

        # Validate no references field for single CWE
        self.assertIsNone(finding.references)

    def test_parse_sca_findings_status_ignored_not_vuln(self):
        findings = self.parse_json("snyk_sca_scan_api_many_vuln.json")

        # 2 - Ignored - Not Vulnerable, does not expire - following JSON structure order
        finding = findings[1]
        # Basic identification
        self.assertEqual("834bd190-3f57-46bb-b9ef-e11fee859ab4", finding.unique_id_from_tool)

        # attributes.classes -> CWE
        self.assertEqual(122, finding.cwe)

        # attributes.coordinates -> fix_available, component info
        self.assertEqual(True, finding.fix_available)
        self.assertEqual("pillow", finding.component_name)
        self.assertEqual("9.5.0", finding.component_version)
        self.assertEqual("pillow", finding.file_path)

        # attributes.created_at -> date
        self.assertEqual("2025-09-11", finding.date)

        # attributes.effective_severity_level -> severity
        self.assertEqual("Critical", finding.severity)

        # attributes.exploit_details -> impact (exploit sources)
        self.assertIn("Exploit Sources: CISA, PoC in GitHub, Snyk", finding.impact)

        # attributes.ignored -> false_p, active, verified, out_of_scope
        self.assertEqual(True, finding.false_p)
        self.assertEqual(False, finding.active)  # ignored issues are not active
        self.assertEqual(True, finding.verified)  # Definatelly verified
        self.assertEqual(False, finding.out_of_scope)  # Ignored, but not out of scope

        # attributes.key -> vuln_id_from_tool
        self.assertEqual("SNYK-PYTHON-PILLOW-5918878", finding.vuln_id_from_tool)

        # attributes.problems -> unsaved_vulnerability_ids, impact
        expected_ids = ["SNYK-PYTHON-PILLOW-5918878", "CVE-2023-4863"]
        self.assertEqual(expected_ids, finding.unsaved_vulnerability_ids)
        self.assertIn("Source: SNYK", finding.impact)
        self.assertIn("Type: vulnerability", finding.impact)
        self.assertIn("Package: pillow", finding.impact)
        self.assertIn("Version: 9.5.0", finding.impact)

        # attributes.risk -> severity_justification
        self.assertIn("Risk Score: 649", finding.severity_justification)

        # attributes.severities -> CVSS data (multiple severities, should get first matching v3.1)
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H/E:H", finding.cvssv3)
        self.assertEqual(9.6, finding.cvssv3_score)

        # attributes.status -> active, is_mitigated, risk_accepted
        self.assertEqual(False, finding.is_mitigated)
        self.assertEqual(False, finding.risk_accepted)

        # attributes.title
        self.assertEqual("Heap-based Buffer Overflow", finding.title)

        # attributes.type -> static_finding, dynamic_finding
        self.assertEqual(True, finding.static_finding)
        self.assertEqual(False, finding.dynamic_finding)

        # Validate no references field for single CWE
        self.assertIsNone(finding.references)

    def test_parse_sca_findings_status_ignored_temporary(self):
        findings = self.parse_json("snyk_sca_scan_api_many_vuln.json")

        # 3 - Ignored Temporary - expires - following JSON structure order
        finding = findings[2]
        # Basic identification
        self.assertEqual("f6c21bae-ceba-4239-9568-bae7dc2b16c9", finding.unique_id_from_tool)

        # attributes.classes -> CWE
        self.assertEqual(95, finding.cwe)

        # attributes.coordinates -> fix_available, component info
        self.assertEqual(True, finding.fix_available)
        self.assertEqual("pillow", finding.component_name)
        self.assertEqual("9.5.0", finding.component_version)

        # attributes.created_at -> date
        self.assertEqual("2025-09-11", finding.date)

        # attributes.effective_severity_level -> severity
        self.assertEqual("High", finding.severity)

        # attributes.exploit_details -> impact (exploit sources)
        self.assertIn("Exploit Sources: Snyk", finding.impact)

        # attributes.ignored -> false_p, active, verified, out_of_scope
        self.assertEqual(True, finding.false_p)  # There is no way to tell if that's temporarily ignored or not from JSON
        self.assertEqual(False, finding.active)  # ignored issues are not active
        self.assertEqual(True, finding.verified)
        self.assertEqual(False, finding.out_of_scope)

        # attributes.key -> vuln_id_from_tool
        self.assertEqual("SNYK-PYTHON-PILLOW-6182918", finding.vuln_id_from_tool)

        # attributes.problems -> impact
        self.assertIn("Source: SNYK", finding.impact)
        self.assertIn("Type: vulnerability", finding.impact)
        self.assertIn("Package: pillow", finding.impact)
        self.assertIn("Version: 9.5.0", finding.impact)

        # attributes.risk -> severity_justification
        self.assertIn("Risk Score: 239", finding.severity_justification)

        # attributes.severities -> CVSS data

        # attributes.status -> active, is_mitigated, risk_accepted
        self.assertEqual(False, finding.is_mitigated)
        self.assertEqual(False, finding.risk_accepted)  # Should be True. Again cannot tell from Json. Temporarily ignored issues are risk accepted.

        # attributes.title
        self.assertEqual("Eval Injection", finding.title)

        # attributes.type -> static_finding, dynamic_finding
        self.assertEqual(True, finding.static_finding)
        self.assertEqual(False, finding.dynamic_finding)

        # Validate no references field for single CWE
        self.assertIsNone(finding.references)

    def test_parse_sca_findings_status_wont_be_fixed(self):
        findings = self.parse_json("snyk_sca_scan_api_many_vuln.json")

        # 4 - Won't fixed issue - without date - following JSON structure order
        finding = findings[3]
        # Basic identification
        self.assertEqual("b827a682-67a5-4a7e-94df-26ebc4156f74", finding.unique_id_from_tool)

        # attributes.classes -> CWE
        self.assertEqual(94, finding.cwe)

        # attributes.coordinates -> fix_available, component info
        self.assertEqual(True, finding.fix_available)
        self.assertEqual("setuptools", finding.component_name)
        self.assertEqual("40.5.0", finding.component_version)

        # attributes.created_at -> date
        self.assertEqual("2025-09-11", finding.date)

        # attributes.effective_severity_level -> severity
        self.assertEqual("High", finding.severity)

        # attributes.exploit_details -> impact (exploit sources)
        self.assertIn("Exploit Sources: Snyk", finding.impact)

        # attributes.ignored -> false_p, active, verified, out_of_scope
        self.assertEqual(True, finding.false_p)
        self.assertEqual(False, finding.active)  # ignored issues are not active
        self.assertEqual(True, finding.verified)
        self.assertEqual(False, finding.out_of_scope)  # This one is ignored

        # attributes.key -> vuln_id_from_tool
        self.assertEqual("SNYK-PYTHON-SETUPTOOLS-7448482", finding.vuln_id_from_tool)

        # attributes.problems -> impact
        self.assertIn("Source: SNYK", finding.impact)
        self.assertIn("Type: vulnerability", finding.impact)
        self.assertIn("Package: setuptools", finding.impact)
        self.assertIn("Version: 40.5.0", finding.impact)

        # attributes.risk -> severity_justification
        self.assertIn("Risk Score: 205", finding.severity_justification)

        # attributes.severities -> CVSS data

        # attributes.status -> active, is_mitigated, risk_accepted
        self.assertEqual(False, finding.is_mitigated)
        self.assertEqual(False, finding.risk_accepted)  # Should be True. Again cannot tell from Json.

        # attributes.title
        self.assertEqual("Improper Control of Generation of Code ('Code Injection')", finding.title)

        # attributes.type -> static_finding, dynamic_finding
        self.assertEqual(True, finding.static_finding)
        self.assertEqual(False, finding.dynamic_finding)

        # Validate no references field for single CWE
        self.assertIsNone(finding.references)

    def test_parse_sca_findings_status_resolved(self):
        findings = self.parse_json("snyk_sca_scan_api_many_vuln.json")

        # 5 - Resolved issue ( fixed, and does not appear in UI) - following JSON structure order
        finding = findings[4]
        # Basic identification
        self.assertEqual("681e5433-d988-4347-8cb3-572723eac067", finding.unique_id_from_tool)

        # attributes.classes -> CWE
        self.assertEqual(444, finding.cwe)

        # attributes.coordinates -> fix_available, component info
        self.assertEqual(True, finding.fix_available)
        self.assertEqual("h11", finding.component_name)
        self.assertEqual("0.14.0", finding.component_version)

        # attributes.created_at -> date
        self.assertEqual("2025-06-03", finding.date)

        # attributes.effective_severity_level -> severity
        self.assertEqual("Critical", finding.severity)

        # attributes.exploit_details (empty sources - no exploit info in impact)

        # attributes.ignored -> false_p, active, verified, out_of_scope
        self.assertEqual(False, finding.false_p)
        self.assertEqual(False, finding.active)  # resolved issues are not active
        self.assertEqual(True, finding.verified)
        self.assertEqual(False, finding.out_of_scope)  # Not ignored

        # attributes.key -> vuln_id_from_tool
        self.assertEqual("SNYK-PYTHON-H11-10293728", finding.vuln_id_from_tool)

        # attributes.problems -> unsaved_vulnerability_ids, impact
        expected_ids = ["CVE-2025-43859", "SNYK-PYTHON-H11-10293728"]
        self.assertEqual(expected_ids, finding.unsaved_vulnerability_ids)
        self.assertIn("Source:", finding.impact)  # Could be SNYK or NVD based on problems array
        self.assertIn("Type: vulnerability", finding.impact)
        self.assertIn("Package: h11", finding.impact)
        self.assertIn("Version: 0.14.0", finding.impact)

        # attributes.resolution (present but not directly mapped to finding fields)

        # attributes.risk -> severity_justification (not present in this finding)
        self.assertIsNone(finding.severity_justification)  # This resolved issue should not have severity_justification since risk.score is not present in JSON

        # attributes.severities -> CVSS data (has both v3.1 and v4.0)
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", finding.cvssv3)
        self.assertEqual(9.1, finding.cvssv3_score)
        self.assertEqual("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", finding.cvssv4)
        self.assertEqual(9.3, finding.cvssv4_score)

        # attributes.status -> active, is_mitigated, risk_accepted
        self.assertEqual(True, finding.is_mitigated)
        self.assertEqual(False, finding.risk_accepted)

        # attributes.title
        self.assertEqual("HTTP Request Smuggling", finding.title)

        # attributes.type -> static_finding, dynamic_finding
        self.assertEqual(True, finding.static_finding)
        self.assertEqual(False, finding.dynamic_finding)

        # Validate no references field for single CWE
        self.assertIsNone(finding.references)

    def test_deduplication_fields_match_other_snyk_scans_for_sca(self):
        findings = self.parse_json("snyk_sca_scan_api_many_vuln.json")
        finding = findings[0]
        # currently deduplication is  done via 4 fields 'vuln_id_from_tool' 'file_path' 'component_name' and 'component_version'
        self.assertEqual("SNYK-PYTHON-PILLOW-6219984", finding.vuln_id_from_tool)
        # !!! there is no way to make this field match Sarif value chain 'python-tool > watchgod > anyio'
        self.assertEqual("pillow", finding.file_path)
        self.assertEqual("pillow", finding.component_name)
        self.assertEqual("9.5.0", finding.component_version)

    def test_deduplication_fields_match_other_snyk_scans_for_code(self):
        findings = self.parse_json("snyk_code_scan_api_many_vuln.json")
        finding = findings[0]
        # currently deduplication is only done via 2 fields 'vuln_id_from_tool' and 'file_path'
        # !!! sarif value is something like 'python/CodeInjection', cannot be matched
        self.assertEqual("9a29d87f-aa94-47eb-b46f-375b293a8631", finding.vuln_id_from_tool)
        self.assertEqual("path/path/file.abc", finding.file_path)
