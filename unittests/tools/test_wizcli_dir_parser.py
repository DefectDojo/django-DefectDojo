from dojo.models import Test
from dojo.tools.wizcli_dir.parser import WizcliDirParser
from unittests.dojo_test_case import DojoTestCase


class TestWizcliDirParser(DojoTestCase):
    def test_no_findings(self):
        with open("unittests/scans/wizcli_dir/wizcli_dir_zero_vul.json") as testfile:
            parser = WizcliDirParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(len(findings), 0)

    def test_one_findings(self):
        with open("unittests/scans/wizcli_dir/wizcli_dir_one_vul.json") as testfile:
            parser = WizcliDirParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("google.golang.org/protobuf - CVE-2024-24786", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("/grpc/proto/go.mod", finding.file_path)
            self.assertIn(
                "**Library Name**: google.golang.org/grpc\n"
                "**Library Version**: 1.48.0\n"
                "**Library Path**: /grpc/proto/go.mod\n"
                "**Vulnerability Name**: CVE-2023-44487\n"
                "**Fixed Version**: 1.56.3\n"
                "**Source**: https://github.com/advisories/GHSA-qppj-fm5r-hxr3\n"
                "**Description**: N/A\n"
                "**Score**: N/A\n"
                "**Exploitability Score**: N/A\n"
                "**Has Exploit**: True\n"
                "**Has CISA KEV Exploit**: True\n", finding.description)

    def test_multiple_findings(self):
        with open("unittests/scans/wizcli_dir/wizcli_dir_many_vul.json") as testfile:
            parser = WizcliDirParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            finding = findings[0]
            self.assertEqual("google.golang.org/grpc - GHSA-m425-mq94-257g", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("/grpc/proto/go.mod", finding.file_path)
            self.assertIn(
                "**Library Name**: google.golang.org/grpc\n"
                "**Library Version**: 1.48.0\n"
                "**Library Path**: /grpc/proto/go.mod\n"
                "**Vulnerability Name**: CVE-2023-44487\n"
                "**Fixed Version**: 1.56.3\n"
                "**Source**: https://github.com/advisories/GHSA-qppj-fm5r-hxr3\n"
                "**Description**: N/A\n"
                "**Score**: N/A\n"
                "**Exploitability Score**: N/A\n"
                "**Has Exploit**: True\n"
                "**Has CISA KEV Exploit**: True\n", finding.description)

            finding = findings[1]
            self.assertEqual("Passwords And Secrets - Certificate for evilorg.com", finding.title)
            self.assertEqual("LOW", finding.severity)
            self.assertEqual("Dockerfile", finding.file_path)
            self.assertEqual(64, finding.line)
            self.assertIn(
                "**Secret ID**: null\n"
                "**Secret Name**: Passwords And Secrets - Certificate for evilorg.com\n"
                "**File Name**: docker-compose.yaml\n"
                "**Line Number**: 239\n"
                "**Match Secret Type**: CERTIFICATE\n", finding.description)
