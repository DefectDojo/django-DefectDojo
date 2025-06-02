from dojo.models import Test
from dojo.tools.wizcli_iac.parser import WizcliIacParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestWizcliIacParser(DojoTestCase):
    def test_no_findings(self):
        with (get_unit_tests_scans_path("wizcli_iac") / "wizcli_iac_zero_vul.json").open(encoding="utf-8") as testfile:
            parser = WizcliIacParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(len(findings), 0)

    def test_one_findings(self):
        with (get_unit_tests_scans_path("wizcli_iac") / "wizcli_iac_one_vul.json").open(encoding="utf-8") as testfile:
            parser = WizcliIacParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual(
                "Bucket usage logs should be enabled - google_storage_bucket[elastic-snapshots]",
                finding.title,
            )
            self.assertEqual("Low", finding.severity)
            self.assertEqual("states/dev/storage.tf", finding.file_path)
            self.assertEqual(1, finding.line)
            self.assertIn(
                "**Rule**: Bucket usage logs should be enabled (ID: `bd9e69dd-93a1-4122-900a-992135c62572`)\n"
                "**Severity**: Low\n"
                "**Resource**: `google_storage_bucket[elastic-snapshots]`\n"
                "**File**: `states/dev/storage.tf`\n"
                "**Line**: 1\n"
                '**Code Snippet**: ```\nresource "google_storage_bucket" "elastic-snapshots" {\n```\n'
                "\n**Finding Details**:\n"
                "- **Expected**: 'logging' should be set\n"
                "- **Found**: 'logging' is undefined\n"
                "- **File Type**: TERRAFORM",
                finding.description,
            )
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)
            self.assertTrue(finding.active)
            self.assertEqual("bd9e69dd-93a1-4122-900a-992135c62572", finding.vuln_id_from_tool)

    def test_multiple_findings(self):
        with (get_unit_tests_scans_path("wizcli_iac") / "wizcli_iac_many_vul.json").open(encoding="utf-8") as testfile:
            parser = WizcliIacParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(25, len(findings))

            # Test first finding
            finding = findings[0]
            self.assertEqual(
                "Apk Add Using Local Cache Path - FROM={{registry.gitlab.com/evilorg.com/infra/images/go-lang-1.18-alpine3.17:latest as builder}}.{{RUN apk add --update make git musl-dev gcc}}",
                finding.title,
            )
            self.assertEqual("Info", finding.severity)
            self.assertEqual("Dockerfile", finding.file_path)
            self.assertEqual(8, finding.line)
            self.assertIn(
                "**Rule**: Apk Add Using Local Cache Path (ID: `4ac84116-456f-4d60-9e12-187607266faf`)\n"
                "**Severity**: Info\n"
                "**Resource**: `FROM={{registry.gitlab.com/evilorg.com/infra/images/go-lang-1.18-alpine3.17:latest as builder}}.{{RUN apk add --update make git musl-dev gcc}}`\n"
                "**File**: `Dockerfile`\n"
                "**Line**: 8\n"
                "**Code Snippet**: ```\nRUN apk add --update make git musl-dev gcc\n```\n"
                "\n**Finding Details**:\n"
                "- **Expected**: 'RUN' should not contain 'apk add' command without '--no-cache' switch\n"
                "- **Found**: 'RUN' contains 'apk add' command without '--no-cache' switch\n"
                "- **File Type**: DOCKERFILE",
                finding.description,
            )
            self.assertTrue(finding.static_finding)
            self.assertFalse(finding.dynamic_finding)
            self.assertTrue(finding.active)
            self.assertEqual("4ac84116-456f-4d60-9e12-187607266faf", finding.vuln_id_from_tool)

            # Test second finding
            finding = findings[1]
            self.assertEqual(
                "Healthcheck Instruction Missing - FROM={{registry.gitlab.com/evilorg.com/infra/images/alpine-3.9:latest}}",
                finding.title,
            )
            self.assertEqual("Low", finding.severity)
            self.assertEqual("Dockerfile", finding.file_path)
            self.assertEqual(58, finding.line)
            self.assertIn(
                "**Rule**: Healthcheck Instruction Missing (ID: `ab1043e3-1eeb-4e38-9ca9-7ec0e99fe2ba`)\n"
                "**Severity**: Low\n"
                "**Resource**: `FROM={{registry.gitlab.com/evilorg.com/infra/images/alpine-3.9:latest}}`\n"
                "**File**: `Dockerfile`\n"
                "**Line**: 58\n"
                "**Code Snippet**: ```\nFROM registry.gitlab.com/evilorg.com/infra/images/alpine-3.9:latest\n```\n"
                "\n**Finding Details**:\n"
                "- **Expected**: Dockerfile should contain instruction 'HEALTHCHECK'\n"
                "- **Found**: Dockerfile doesn't contain instruction 'HEALTHCHECK'\n"
                "- **File Type**: DOCKERFILE",
                finding.description,
            )
