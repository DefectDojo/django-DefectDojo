from django.test import TestCase
from dojo.tools.wizcli_img.parser import WizcliImgParser
from dojo.models import Test


class TestWizcliImgParserParser(TestCase):
    def test_no_findings(self):
        with open("unittests/scans/wizcli_dir/wizcli_dir_zero_vul.json") as testfile:
            parser = WizcliImgParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(len(findings), 0)

    def test_one_findings(self):
        with open("unittests/scans/wizcli_dir/wizcli_dir_one_vul.json") as testfile:
            parser = WizcliImgParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("google.golang.org/protobuf - CVE-2024-24786", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("/grpc/proto/go.mod", finding.file_path)
            self.assertIn(
                f"**Library Name**: google.golang.org/grpc\n"
                f"**Library Version**: 1.48.0\n"
                f"**Library Path**: /grpc/proto/go.mod\n"
                f"**Vulnerability Name**: CVE-2023-44487\n"
                f"**Fixed Version**: 1.56.3\n"
                f"**Source**: https://github.com/advisories/GHSA-qppj-fm5r-hxr3\n"
                f"**Description**: N/A\n"
                f"**Score**: N/A\n"
                f"**Exploitability Score**: N/A\n"
                f"**Has Exploit**: True\n"
                f"**Has CISA KEV Exploit**: True\n", finding.description)

    def test_multiple_findings(self):
        with open("unittests/scans/wizcli_dir/wizcli_dir_many_vul.json") as testfile:
            parser = WizcliImgParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            finding = findings[0]
            self.assertEqual("google.golang.org/grpc - GHSA-m425-mq94-257g", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("/grpc/proto/go.mod", finding.file_path)
            self.assertIn(
                f"**Library Name**: google.golang.org/grpc\n"
                f"**Library Version**: 1.48.0\n"
                f"**Library Path**: /grpc/proto/go.mod\n"
                f"**Vulnerability Name**: CVE-2023-44487\n"
                f"**Fixed Version**: 1.56.3\n"
                f"**Source**: https://github.com/advisories/GHSA-qppj-fm5r-hxr3\n"
                f"**Description**: N/A\n"
                f"**Score**: N/A\n"
                f"**Exploitability Score**: N/A\n"
                f"**Has Exploit**: True\n"
                f"**Has CISA KEV Exploit**: True\n", finding.description)

            finding = findings[1]
            self.assertEqual("Passwords And Secrets - Certificate for evilorg.com", finding.title)
            self.assertEqual("LOW", finding.severity)
            self.assertEqual("Dockerfile", finding.file_path)
            self.assertEqual(64, finding.line)
            self.assertIn(
                f"**Secret ID**: null\n"
                f"**Secret Name**: Passwords And Secrets - Certificate for evilorg.com\n"
                f"**File Name**: docker-compose.yaml\n"
                f"**Line Number**: 239\n"
                f"**Match Secret Type**: CERTIFICATE\n", finding.description)
