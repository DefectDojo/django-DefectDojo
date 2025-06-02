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
            self.assertEqual(61, len(findings))
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
            self.assertEqual(478, len(findings))

            # Test first finding
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

            # Test second finding
            finding = findings[1]
            self.assertEqual(
                "Bucket usage logs should be enabled - google_storage_bucket[vault-store]",
                finding.title,
            )
            self.assertEqual("Low", finding.severity)
            self.assertEqual("states/dev/storage.tf", finding.file_path)
            self.assertEqual(17, finding.line)
            self.assertIn(
                "**Rule**: Bucket usage logs should be enabled (ID: `bd9e69dd-93a1-4122-900a-992135c62572`)\n"
                "**Severity**: Low\n"
                "**Resource**: `google_storage_bucket[vault-store]`\n"
                "**File**: `states/dev/storage.tf`\n"
                "**Line**: 17\n"
                '**Code Snippet**: ```\nresource "google_storage_bucket" "vault-store" {\n```\n'
                "\n**Finding Details**:\n"
                "- **Expected**: 'logging' should be set\n"
                "- **Found**: 'logging' is undefined\n"
                "- **File Type**: TERRAFORM",
                finding.description,
            )
