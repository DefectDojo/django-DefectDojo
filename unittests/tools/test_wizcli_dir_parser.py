from dojo.models import Test
from dojo.tools.wizcli_dir.parser import WizcliDirParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestWizcliDirParser(DojoTestCase):
    def test_no_findings(self):
        with (get_unit_tests_scans_path("wizcli_dir") / "wizcli_dir_zero_vul.json").open(encoding="utf-8") as testfile:
            parser = WizcliDirParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(len(findings), 0)

    def test_one_findings(self):
        with (get_unit_tests_scans_path("wizcli_dir") / "wizcli_dir_one_vul.json").open(encoding="utf-8") as testfile:
            parser = WizcliDirParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("github.com/golang-jwt/jwt/v4 4.5.1 - CVE-2025-30204", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("/settlements/go.mod", finding.file_path)
            self.assertIn(
                "**Vulnerability**: `CVE-2025-30204`\n"
                "**Severity**: High\n"
                "**Library**: `github.com/golang-jwt/jwt/v4`\n"
                "**Version**: `4.5.1`\n"
                "**Path/Manifest**: `/settlements/go.mod`\n"
                "**Fixed Version**: 4.5.2\n"
                "**Source**: https://github.com/advisories/GHSA-mh63-6h87-95cp\n"
                "**Has Exploit (Known)**: False\n"
                "**In CISA KEV**: False",
                finding.description,
            )
            self.assertEqual("Update `github.com/golang-jwt/jwt/v4` to version `4.5.2` or later in path/manifest `/settlements/go.mod`.", finding.mitigation)
            self.assertEqual("CVE-2025-30204", finding.cve)
            self.assertEqual("https://github.com/advisories/GHSA-mh63-6h87-95cp", finding.references)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)
            self.assertTrue(finding.active)

    def test_multiple_findings(self):
        with (get_unit_tests_scans_path("wizcli_dir") / "wizcli_dir_many_vul.json").open(encoding="utf-8") as testfile:
            parser = WizcliDirParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(204, len(findings))

            # Test first finding
            finding = findings[0]
            self.assertEqual("github.com/golang-jwt/jwt/v4 4.5.1 - CVE-2025-30204", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("/settlements/go.mod", finding.file_path)
            self.assertIn(
                "**Vulnerability**: `CVE-2025-30204`\n"
                "**Severity**: High\n"
                "**Library**: `github.com/golang-jwt/jwt/v4`\n"
                "**Version**: `4.5.1`\n"
                "**Path/Manifest**: `/settlements/go.mod`\n"
                "**Fixed Version**: 4.5.2\n"
                "**Source**: https://github.com/advisories/GHSA-mh63-6h87-95cp",
                finding.description,
            )
            self.assertEqual("CVE-2025-30204", finding.cve)
            self.assertEqual("https://github.com/advisories/GHSA-mh63-6h87-95cp", finding.references)

            # Test second finding
            finding = findings[1]
            self.assertEqual("github.com/golang-jwt/jwt/v5 5.2.1 - CVE-2025-30204", finding.title)
            self.assertEqual("High", finding.severity)
            self.assertEqual("/settlements/go.mod", finding.file_path)
            self.assertIn(
                "**Vulnerability**: `CVE-2025-30204`\n"
                "**Severity**: High\n"
                "**Library**: `github.com/golang-jwt/jwt/v5`\n"
                "**Version**: `5.2.1`\n"
                "**Path/Manifest**: `/settlements/go.mod`\n"
                "**Fixed Version**: 5.2.2\n"
                "**Source**: https://github.com/advisories/GHSA-mh63-6h87-95cp",
                finding.description,
            )
            self.assertEqual("CVE-2025-30204", finding.cve)
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)
            self.assertTrue(finding.active)
