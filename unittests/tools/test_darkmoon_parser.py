from dojo.models import Finding, Test
from dojo.tools.darkmoon.parser import DarkmoonParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestDarkmoonParser(DojoTestCase):

    def locations_of(self, finding):
        """Return the finding's locations or endpoints, whichever the feature flag populated."""
        return list(getattr(finding, "unsaved_locations", []) or getattr(finding, "unsaved_endpoints", []))

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("darkmoon") / "no_vuln.json").open(encoding="utf-8") as testfile:
            parser = DarkmoonParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_one_finding(self):
        with (get_unit_tests_scans_path("darkmoon") / "one_vuln.json").open(encoding="utf-8") as testfile:
            parser = DarkmoonParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Boolean-based blind SQL injection in product search", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertTrue(finding.active)
            self.assertTrue(finding.verified)
            self.assertTrue(finding.dynamic_finding)
            self.assertFalse(finding.static_finding)
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", finding.cvssv3)
            self.assertEqual(8.6, finding.cvssv3_score)
            self.assertEqual(["CVE-2026-55512"], finding.unsaved_vulnerability_ids)
            self.assertEqual("search-controller", finding.component_name)
            # node_id is the shared infrastructure node, not a per-finding id, so
            # it must not be mapped to vuln_id_from_tool.
            self.assertIsNone(getattr(finding, "vuln_id_from_tool", None))
            self.assertEqual(
                "Use parameterised queries / prepared statements for all database access.",
                finding.mitigation,
            )
            self.assertIn("exploited", finding.unsaved_tags)
            self.assertIn("php", finding.unsaved_tags)
            self.assertIn("sql_injection", finding.unsaved_tags)
            self.assertIn("Exploitation status:** Exploited", finding.description)
            self.assertIn("MITRE ATT&CK:** T1190", finding.description)
            self.assertIn("ISO 27001 control:** A.8.28", finding.description)
            # Evidence is nested under "evidence" in the real report.
            self.assertIn("Evidence:", finding.description)
            self.assertIsNotNone(finding.steps_to_reproduce)
            self.assertIn("**Commands:**", finding.steps_to_reproduce)
            self.assertIn("**Logs:**", finding.steps_to_reproduce)
            self.assertIsNotNone(finding.unsaved_request)
            self.assertIsNotNone(finding.unsaved_response)
            self.assertEqual(1, len(self.locations_of(finding)))

    def test_parse_many_findings(self):
        with (get_unit_tests_scans_path("darkmoon") / "many_vulns.json").open(encoding="utf-8") as testfile:
            parser = DarkmoonParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(4, len(findings))

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual(
                    "Unauthenticated remote code execution in file upload handler",
                    finding.title,
                )
                self.assertEqual("Critical", finding.severity)
                self.assertTrue(finding.active)
                self.assertTrue(finding.verified)
                self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", finding.cvssv3)
                self.assertEqual(9.8, finding.cvssv3_score)
                self.assertEqual(["CVE-2026-12345"], finding.unsaved_vulnerability_ids)
                self.assertEqual("upload-handler", finding.component_name)
                self.assertIsNotNone(finding.unsaved_request)
                self.assertIsNotNone(finding.unsaved_response)
                self.assertIn("```", finding.steps_to_reproduce)

            with self.subTest(i=1):
                # status "resolved" -> inactive + mitigated
                finding = findings[1]
                self.assertEqual(
                    "Stored cross-site scripting in profile display name",
                    finding.title,
                )
                self.assertEqual("High", finding.severity)
                self.assertFalse(finding.active)
                self.assertTrue(finding.is_mitigated)
                self.assertTrue(finding.verified)
                self.assertEqual(8.2, finding.cvssv3_score)
                self.assertEqual("profile-renderer", finding.component_name)

            with self.subTest(i=2):
                finding = findings[2]
                self.assertEqual(
                    "Server-side request forgery in URL preview feature",
                    finding.title,
                )
                self.assertEqual("Medium", finding.severity)
                self.assertTrue(finding.active)
                self.assertFalse(finding.verified)
                # Minimal finding: no cvss vector, no cve, component from agent.
                self.assertIsNone(finding.cvssv3)
                self.assertEqual(6.5, finding.cvssv3_score)
                self.assertEqual("nodejs", finding.component_name)
                self.assertIn("Unconfirmed", finding.description)

            with self.subTest(i=3):
                # bare-path endpoint ("/api/login") has no host, so it is skipped.
                finding = findings[3]
                self.assertEqual("Low", finding.severity)
                self.assertTrue(finding.active)
                self.assertFalse(finding.verified)
                self.assertEqual(0, len(self.locations_of(finding)))

    def test_endpoints_are_valid(self):
        with (get_unit_tests_scans_path("darkmoon") / "many_vulns.json").open(encoding="utf-8") as testfile:
            parser = DarkmoonParser()
            findings = parser.get_findings(testfile, Test())
            # Only three of the four findings carry a host-qualified endpoint.
            with_locations = [f for f in findings if self.locations_of(f)]
            self.assertEqual(3, len(with_locations))
            self.validate_locations(with_locations)
