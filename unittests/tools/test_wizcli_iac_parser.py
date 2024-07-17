from dojo.models import Test
from dojo.tools.wiz.parser import WizcliIaCParser

from ..dojo_test_case import DojoTestCase


class TestWizcliIaCParser(DojoTestCase):
    def test_no_findings(self):
        with open("unittests/scans/wizcli_iac/wizcli_iac_zero_vul.json") as testfile:
            parser = WizcliIaCParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(len(findings), 0)

    def test_one_findings(self):
        with open("unittests/scans/wizcli_iac/wizcli_iac_one_vul.json") as testfile:
            parser = WizcliIaCParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("docker-compose.yaml", finding.file_path)
            self.assertEqual(64, finding.line)
            self.assertIn(
                f"**Rule ID**: 4ac84116-456f-4d60-9e12-187607266faf \n"
                f"**Rule Name**: Apk Add Using Local Cache Path\n"
                f"**Resource Name**: FROM={{registry.gitlab.com/evilorg.com/infra/images/go-lang-1.18-alpine3.17:latest as builder}}.{{RUN apk add --update make git musl-dev gcc}}\n"
                f"**File Name**: Dockerfile\n"
                f"**Line Number**: 32\n"
                f"**Match Content**: RUN apk add --update make git musl-dev gcc\n"
                f"**Expected**: 'RUN' should not contain 'apk add' command without '--no-cache' switch\n"
                f"**Found**: 'RUN' contains 'apk add' command without '--no-cache' switch\n"
                f"**File Type**: DOCKERFILE\n", finding.description)

    def test_multiple_findings(self):
        with open("unittests/scans/wizcli_iac/wizcli_iac_many_vul.json") as testfile:
            parser = WizcliIaCParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("docker-compose.yaml", finding.file_path)
            self.assertEqual(64, finding.line)
            self.assertIn(
                f"**Rule ID**: 4ac84116-456f-4d60-9e12-187607266faf \n"
                f"**Rule Name**: Apk Add Using Local Cache Path\n"
                f"**Resource Name**: FROM={{registry.gitlab.com/evilorg.com/infra/images/go-lang-1.18-alpine3.17:latest as builder}}.{{RUN apk add --update make git musl-dev gcc}}\n"
                f"**File Name**: Dockerfile\n"
                f"**Line Number**: 32\n"
                f"**Match Content**: RUN apk add --update make git musl-dev gcc\n"
                f"**Expected**: 'RUN' should not contain 'apk add' command without '--no-cache' switch\n"
                f"**Found**: 'RUN' contains 'apk add' command without '--no-cache' switch\n"
                f"**File Type**: DOCKERFILE\n", finding.description)

            finding = findings[1]
            self.assertEqual("LOW", finding.severity)
            self.assertEqual("Dockerfile", finding.file_path)
            self.assertEqual(64, finding.line)
            self.assertIn(
                f"**Secret ID**: null\n"
                f"**Secret Name**: Passwords And Secrets - Certificate for evilorg.com\n"
                f"**File Name**: docker-compose.yaml\n"
                f"**Line Number**: 239\n"
                f"**Match Secret Type**: CERTIFICATE\n", finding.description)
