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
            self.assertEqual("OS Pkg: libcrypto3 3.3.1-r0 - CVE-2024-5535", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertIsNone(finding.file_path)
            self.assertIn(
                "**Vulnerability**: `CVE-2024-5535`\n"
                "**Severity**: Low\n"
                "**OS Package**: `libcrypto3`\n"
                "**Version**: `3.3.1-r0`\n"
                "**Fixed Version**: 3.3.1-r1\n"
                "**Source**: https://security.alpinelinux.org/vuln/CVE-2024-5535",
                finding.description,
            )
            self.assertEqual("CVE-2024-5535", finding.cve)
            self.assertEqual("https://security.alpinelinux.org/vuln/CVE-2024-5535", finding.references)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)
            self.assertTrue(finding.active)

            # Test second finding
            finding = findings[1]
            self.assertEqual("OS Pkg: libssl3 3.3.1-r0 - CVE-2024-5535", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertIsNone(finding.file_path)
            self.assertIn(
                "**Vulnerability**: `CVE-2024-5535`\n"
                "**Severity**: Low\n"
                "**OS Package**: `libssl3`\n"
                "**Version**: `3.3.1-r0`\n"
                "**Fixed Version**: 3.3.1-r1\n"
                "**Source**: https://security.alpinelinux.org/vuln/CVE-2024-5535",
                finding.description,
            )
            self.assertEqual("CVE-2024-5535", finding.cve)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)
            self.assertTrue(finding.active)
