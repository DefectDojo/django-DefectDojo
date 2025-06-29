from dojo.models import Test
from dojo.tools.wizcli_img.parser import WizcliImgParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestWizcliImgParser(DojoTestCase):
    def test_no_findings(self):
        with (get_unit_tests_scans_path("wizcli_img") / "wizcli_img_zero_vul.json").open(encoding="utf-8") as testfile:
            parser = WizcliImgParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(len(findings), 0)

    def test_one_findings(self):
        with (get_unit_tests_scans_path("wizcli_img") / "wizcli_img_one_vul.json").open(encoding="utf-8") as testfile:
            parser = WizcliImgParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual(
                "Secret Detected: GCP Service Account Key (ServiceAccount=test-dev-api-sa@testdev.iam.gserviceaccount.com) (CLOUD_KEY)",
                finding.title,
            )
            self.assertEqual("High", finding.severity)
            self.assertEqual("/app/keys/gcp.json", finding.file_path)
            self.assertEqual(5, finding.line)
            self.assertIn(
                "**Type**: `CLOUD_KEY`\n"
                "**Description**: GCP Service Account Key (ServiceAccount=test-dev-api-sa@testdev.iam.gserviceaccount.com)\n"
                "**File**: `/app/keys/gcp.json`\n"
                "**Line**: 5",
                finding.description,
            )
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)
            self.assertTrue(finding.active)

    def test_multiple_findings(self):
        with (get_unit_tests_scans_path("wizcli_img") / "wizcli_img_many_vul.json").open(encoding="utf-8") as testfile:
            parser = WizcliImgParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(29, len(findings))

            # Test first finding
            finding = findings[0]
            self.assertEqual("OS Pkg: curl 7.64.0-r5 - CVE-2023-38039", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertIsNone(finding.file_path)
            self.assertIn(
                "**Vulnerability**: `CVE-2023-38039`\n"
                "**Severity**: Medium\n"
                "**OS Package**: `curl`\n"
                "**Version**: `7.64.0-r5`\n"
                "**Fixed Version**: N/A\n"
                "**Source**: https://security.alpinelinux.org/vuln/CVE-2023-38039\n"
                "**CVSS Score (from Wiz)**: 7.5\n"
                "**Has Exploit (Known)**: True\n"
                "**In CISA KEV**: False\n\n"
                "**Ignored Policies**:\n"
                "- test Default vulnerabilities policy (ID: 9c6726d0-1ada-4541-b6d6-3da5ca1124f9)\n"
                "- test Default vulnerabilities policy ( Updated ) (ID: 9bf73b16-99e7-4a54-af1e-dcfa1436a8f2)",
                finding.description,
            )
            self.assertEqual("CVE-2023-38039", finding.cve)
            self.assertEqual("https://security.alpinelinux.org/vuln/CVE-2023-38039", finding.references)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)
            self.assertTrue(finding.active)

            # Test second finding
            finding = findings[1]
            self.assertEqual("OS Pkg: curl 7.64.0-r5 - CVE-2020-8231", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertIsNone(finding.file_path)
            self.assertIn(
                "**Vulnerability**: `CVE-2020-8231`\n"
                "**Severity**: High\n"
                "**OS Package**: `curl`\n"
                "**Version**: `7.64.0-r5`\n"
                "**Fixed Version**: 7.66.0-r5\n"
                "**Source**: https://security.alpinelinux.org/vuln/CVE-2020-8231\n"
                "**CVSS Score (from Wiz)**: 7.5\n"
                "**Has Exploit (Known)**: False\n"
                "**In CISA KEV**: False\n\n"
                "**Failed Policies**:\n"
                "- test Default vulnerabilities policy ( Updated ) (ID: 9bf73b16-99e7-4a54-af1e-dcfa1436a8f2)\n"
                "- test Default vulnerabilities policy (ID: 9c6726d0-1ada-4541-b6d6-3da5ca1124f9)",
                finding.description,
            )
            self.assertEqual("CVE-2020-8231", finding.cve)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)
            self.assertTrue(finding.active)
