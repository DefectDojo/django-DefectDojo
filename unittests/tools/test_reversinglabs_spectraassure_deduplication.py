# ruff: noqa: RUF100
# ruff: noqa: I001
import json
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from django.conf import settings

from dojo.models import Finding, Test, User, UserContactInfo
from unittests.dojo_test_case import DojoAPITestCase, get_unit_tests_scans_path

"""
Deduplication of ReversingLabs Spectra Assure findings through real imports (API, database).

The parser test checks unique_id_from_tool; this checks what DefectDojo does with it:
hash_code from HASHCODE_FIELDS_PER_SCANNER (unique_id_from_tool, component_name, component_version),
duplicates across imports, and reimport matching.

run with:

./run-unittest.sh --test-case
    unittests.tools.test_reversinglabs_spectraassure_deduplication.TestReversingLabsSpectraAssureDeduplication

"""

SCAN_TYPE = "ReversingLabs Spectra Assure"
HASH_CODE_FIELDS = ["unique_id_from_tool", "component_name", "component_version"]

_SCANS = get_unit_tests_scans_path("reversinglabs_spectraassure")
AZURE = _SCANS / "azure-cli-2.84.0-x64-report.rl.json"  # 104 CVE + 1 secrets violation
SYNTHETIC = _SCANS / "synthetic-shared-component-report.rl.json"  # 1 CVE + 4 violations on one component

_COMPONENTS = ("5b1f8a52-0c3e-5d7a-9e44-2f6b0a1c9d37", "9d4e7b21-3a8c-5f60-b1d2-6e0c8a4f7b93")  # same binary, 2 paths
_THREAT_ML = "b2d8f3a6-4c1e-4b7d-a5f0-1e9c6d3b8a27"  # threats SQ30108


# mypy gives:  error: Class cannot subclass "DojoAPITestCase" (has type "Any")  [misc]
class TestReversingLabsSpectraAssureDeduplication(DojoAPITestCase):  # type: ignore[misc]
    def setUp(self) -> None:
        super().setUp()

        admin = User.objects.create(username="admin", is_superuser=True, is_staff=True)
        UserContactInfo.objects.create(user=admin, block_execution=True)  # import and dedupe run synchronously
        self.login_as_admin()

        self.system_settings(enable_product_grade=False)
        self.system_settings(enable_github=False)
        self.system_settings(enable_deduplication=True)

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    # ----------------------------------------------------------------
    def import_report(self, path: Path, product: str = "P RL", engagement: int | None = None) -> Test:
        context: dict[str, Any] = (
            {"engagement": engagement}
            if engagement
            else {
                "engagement": None,
                "product_type_name": "PT RL",
                "product_name": product,
                "engagement_name": f"E {product}",
                "auto_create_context": True,
            }
        )
        response = self.import_scan_with_params(
            path,
            scan_type=SCAN_TYPE,
            minimum_severity="Info",
            active=True,
            verified=True,
            **context,
        )
        test: Test = Test.objects.get(id=response["test"])
        return test

    def synthetic_variant(self, name: str, change: Callable[[dict[str, Any]], None]) -> Path:
        data = json.loads(SYNTHETIC.read_text(encoding="utf-8"))
        change(data)
        path = self.tmp / f"{name}.rl.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def findings(self, test: Test) -> list[Finding]:
        return list(Finding.objects.filter(test=test).select_related("duplicate_finding").order_by("id"))

    def duplicates(self, test: Test) -> list[Finding]:
        return [f for f in self.findings(test) if f.duplicate]

    def assert_original(self, test: Test, count: int) -> list[Finding]:
        # a first import: no duplicates, one distinct hash_code per finding
        findings = self.findings(test)
        self.assertEqual(count, len(findings))
        self.assertEqual([], [f.id for f in findings if f.duplicate])
        self.assertTrue(all(f.active for f in findings))
        self.assertEqual(count, len({f.hash_code for f in findings}))
        return findings

    def assert_all_duplicates_of(self, test: Test, originals: list[Finding]) -> None:
        # every finding is a duplicate of the original with the same identity, from the earlier test
        by_identity = {(f.unique_id_from_tool, f.component_name, f.component_version): f for f in originals}
        findings = self.findings(test)
        self.assertEqual(len(originals), len(findings))
        for f in findings:
            original = by_identity[f.unique_id_from_tool, f.component_name, f.component_version]
            self.assertTrue(f.duplicate, f.title)
            self.assertFalse(f.active, f.title)
            self.assertEqual(original.id, f.duplicate_finding.id, f.title)
            self.assertEqual(original.hash_code, f.hash_code, f.title)

    # ----------------------------------------------------------------
    def test_settings_select_hash_code_on_the_identity_fields(self) -> None:
        # without these two entries DefectDojo falls back to the legacy hash of title, cwe, line, file_path, description
        self.assertEqual(HASH_CODE_FIELDS, settings.HASHCODE_FIELDS_PER_SCANNER[SCAN_TYPE])
        self.assertEqual("hash_code", settings.DEDUPLICATION_ALGORITHM_PER_PARSER[SCAN_TYPE])
        self.assertTrue(all(field in settings.HASHCODE_ALLOWED_FIELDS for field in HASH_CODE_FIELDS))

    def test_first_import_has_no_duplicates_and_uses_the_configured_hash_code(self) -> None:
        test = self.import_report(AZURE)
        self.assertEqual(HASH_CODE_FIELDS, test.hash_code_fields)
        self.assertEqual("hash_code", test.deduplication_algorithm)

        findings = self.assert_original(test, 105)
        for f in findings:
            # stored hash_code = the configured fields, not the legacy fallback (no cwe is allowed for this scan type)
            self.assertEqual(f.compute_hash_code(), f.hash_code, f.title)
            self.assertNotEqual(f.compute_hash_code_legacy(), f.hash_code, f.title)

        # one component carrying a CVE and two violations per category: five findings, five hash codes
        self.assert_original(self.import_report(SYNTHETIC, product="P synthetic"), 5)

    def test_same_report_twice_marks_every_finding_of_the_second_import_duplicate(self) -> None:
        first = self.import_report(AZURE)
        originals = self.assert_original(first, 105)

        second = self.import_report(AZURE, engagement=first.engagement.id)
        self.assert_all_duplicates_of(second, originals)

        # the first import is left as it was
        self.assert_original(first, 105)

        # a third import points at the originals too, never at a duplicate
        third = self.import_report(AZURE, engagement=first.engagement.id)
        self.assert_all_duplicates_of(third, originals)

    def test_same_report_in_another_engagement_of_the_product_is_a_duplicate(self) -> None:
        # dedupe scope is the product (deduplication_on_engagement off)
        first = self.import_report(SYNTHETIC)
        originals = self.assert_original(first, 5)

        other = self.create_engagement("E RL other", product=first.engagement.product)
        second = self.import_report(SYNTHETIC, engagement=other.id)
        self.assert_all_duplicates_of(second, originals)

    def test_same_report_in_another_product_is_not_a_duplicate(self) -> None:
        self.assert_original(self.import_report(SYNTHETIC, product="P one"), 5)
        self.assert_original(self.import_report(SYNTHETIC, product="P two"), 5)

    def test_changes_outside_the_identity_still_dedupe(self) -> None:
        # a later scan of the same build: new date, rescored CVE, other violation severity and text, other path
        first = self.import_report(SYNTHETIC)
        originals = self.assert_original(first, 5)

        def rescan(data: dict[str, Any]) -> None:
            data["timestamp"] = "2026-09-20T10:00:00Z"
            metadata = data["report"]["metadata"]
            metadata["vulnerabilities"]["CVE-2099-0001"]["cvss"]["baseScore"] = 5.0
            metadata["vulnerabilities"]["CVE-2099-0001"]["summary"] = "Rescored."
            metadata["violations"][_THREAT_ML]["severity"] = "low"
            metadata["violations"][_THREAT_ML]["description"] = "Reworded."
            metadata["components"][_COMPONENTS[1]]["path"] = "synthetic-installer.exe/old/payload.dll"

        second = self.import_report(self.synthetic_variant("rescan", rescan), engagement=first.engagement.id)
        self.assert_all_duplicates_of(second, originals)

        cve = next(f for f in self.findings(second) if f.vuln_id_from_tool == "CVE-2099-0001")
        self.assertEqual("Medium", cve.severity)  # the duplicate carries the new data

    def test_changes_inside_the_identity_are_new_findings(self) -> None:
        first = self.import_report(SYNTHETIC)
        originals = self.assert_original(first, 5)
        engagement = first.engagement.id

        def new_build(data: dict[str, Any]) -> None:  # another binary: other sha256
            for uuid in _COMPONENTS:
                data["report"]["metadata"]["components"][uuid]["hashes"] = [["sha256", "2" * 64]]

        def new_version(data: dict[str, Any]) -> None:  # same binary, reported with another version
            for uuid in _COMPONENTS:
                data["report"]["metadata"]["components"][uuid]["identity"]["version"] = "1.1"

        test = self.import_report(self.synthetic_variant("new-build", new_build), engagement=engagement)
        self.assertEqual(5, len(self.findings(test)))
        self.assertEqual([], [f.title for f in self.duplicates(test)])

        # component_version is in the hash, for the CVE and the violations alike
        test = self.import_report(self.synthetic_variant("new-version", new_version), engagement=engagement)
        self.assertEqual(5, len(self.findings(test)))
        self.assertEqual([], [f.title for f in self.duplicates(test)])

        def new_rule(data: dict[str, Any]) -> None:  # one violation under another rule id
            data["report"]["metadata"]["violations"][_THREAT_ML]["rule_id"] = "SQ30199"

        test = self.import_report(self.synthetic_variant("new-rule", new_rule), engagement=engagement)
        new = [f for f in self.findings(test) if not f.duplicate]
        self.assertEqual(["threats-SQ30199"], [f.vuln_id_from_tool for f in new])

        # the other four are duplicates of their originals
        duplicates = self.duplicates(test)
        self.assertEqual(4, len(duplicates))
        by_uid = {f.unique_id_from_tool: f for f in originals}
        for f in duplicates:
            self.assertEqual(by_uid[f.unique_id_from_tool].id, f.duplicate_finding.id, f.title)

    def test_reimport_of_the_same_report_changes_nothing(self) -> None:
        test = self.import_report(AZURE)
        before = {f.id: f.hash_code for f in self.assert_original(test, 105)}

        self.reimport_scan_with_params(
            test.id,
            str(AZURE),
            scan_type=SCAN_TYPE,
            minimum_severity="Info",
            active=True,
            verified=True,
            engagement=None,
        )

        after = self.findings(test)
        self.assertEqual(before, {f.id: f.hash_code for f in after})  # matched by hash_code: no new, none closed
        self.assertTrue(all(f.active and not f.is_mitigated and not f.duplicate for f in after))
