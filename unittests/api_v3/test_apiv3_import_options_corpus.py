"""
API v3 port of the remaining import corpus siblings (§10 backlog #1):

  * ``unittests/test_apiv2_scan_import_options.py`` (``ScanImportOptionsTest``) -- empty/full ZAP
    upload scenarios. Ported by subclassing the v2 class and overriding ONLY its ``import_zap_scan``
    helper to hit ``POST /api/v3-alpha/import``; the scenarios + assertions run unchanged.
  * ``unittests/test_importers_closeold.py`` (``TestDojoCloseOld``) -- these are importer *unit*
    tests that call ``DefaultImporter`` directly (no HTTP endpoint), so they cannot be adapted by a
    helper override. The close-old behaviours that are observable through the consolidated endpoint
    are re-expressed here as endpoint-level tests, which additionally exercise the new
    ``close_old_findings_product_scope`` ImportForm field end-to-end. Two originals are intentionally
    NOT ported (the query-column-optimization spy is importer-internal, not endpoint-observable;
    enumerated in the port report).

The v2 base class is referenced via a module attribute so Django's ``test*.py`` discovery does not
also collect it inside this v3 package.
"""
from __future__ import annotations

from pathlib import Path

from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone

import unittests.test_apiv2_scan_import_options as _v2opts
from dojo.models import Engagement, Product, Product_Type, Test
from unittests.dojo_test_case import get_unit_tests_scans_path

from .base import ApiV3TestCase
from .import_corpus_shim import ApiV3ImportShim


class ApiV3ScanImportOptions(ApiV3ImportShim, _v2opts.ScanImportOptionsTest):

    """``ScanImportOptionsTest`` scenarios bound to ``POST /import`` (only the helper is overridden)."""

    def import_zap_scan(self, *, upload_empty_scan=False):
        with Path("tests/zap_sample.xml").open(encoding="utf-8") as file:
            if upload_empty_scan:
                tested_file = SimpleUploadedFile("zap_sample.xml", self.EMPTY_ZAP_SCAN.encode("utf-8"))
            else:
                tested_file = file
            self.payload = {
                "engagement": 1,
                "scan_type": "ZAP Scan",
                "mode": "import",
                "file": tested_file,
            }
            test_ids = list(_v2opts.Test.objects.values_list("id", flat=True))
            r = self.client.post(self.v3_url("import"), self.payload, format="multipart")
            self.assertEqual(200, r.status_code, r.content[:1000])
            return _v2opts.Test.objects.exclude(id__in=test_ids).get()


class ApiV3CloseOldFindingsEndpoint(ApiV3ImportShim, ApiV3TestCase):

    """
    Endpoint-level ports of the close-old importer behaviours (incl. product-scope).

    Assertions read the v3 delta statistics (``new`` == importer new count, ``closed`` == importer
    closed count), which are the exact tuple positions the v2 unit tests assert on.
    """

    ACUNETIX = "Acunetix Scan"
    SEMGREP = "Semgrep JSON Report"

    def _make_product(self, pt_name: str, product_name: str) -> Product:
        product_type, _ = Product_Type.objects.get_or_create(name=pt_name)
        product, _ = Product.objects.get_or_create(name=product_name, description="Test", prod_type=product_type)
        return product

    def _make_engagement(self, name: str, product: Product) -> Engagement:
        engagement, _ = Engagement.objects.get_or_create(
            name=name, product=product, target_start=timezone.now(), target_end=timezone.now(),
        )
        return engagement

    def _import(self, engagement_id: int, scan_path, *, scan_type: str, cof: bool, cofps: bool = False) -> dict:
        payload = {
            "scan_type": scan_type,
            "mode": "import",
            "minimum_severity": "Info",
            "engagement": engagement_id,
            "active": "true",
            "verified": "false",
            "close_old_findings": "true" if cof else "false",
        }
        if cofps:
            payload["close_old_findings_product_scope"] = "true"
        return self._post_v3_import(payload, scan_path, expected=200)

    def test_close_old_findings_engagement_scope(self):
        """Port of ``test_close_old_same_engagement`` (close_old_findings, engagement scope)."""
        product = self._make_product("closeold", "TestDojoCloseOldImporter1")
        engagement = self._make_engagement("Close Old Same Engagement", product)
        many = get_unit_tests_scans_path("acunetix") / "many_findings.xml"
        one = get_unit_tests_scans_path("acunetix") / "one_finding.xml"

        r1 = self._import(engagement.id, many, scan_type=self.ACUNETIX, cof=False)
        self.assertEqual(4, r1["statistics"]["new"])
        self.assertEqual(0, r1["statistics"]["closed"])

        r2 = self._import(engagement.id, many, scan_type=self.ACUNETIX, cof=True)
        self.assertEqual(4, r2["statistics"]["new"])
        self.assertEqual(0, r2["statistics"]["closed"])

        r3 = self._import(engagement.id, one, scan_type=self.ACUNETIX, cof=True)
        self.assertEqual(1, r3["statistics"]["new"])
        self.assertEqual(8, r3["statistics"]["closed"])

    def test_close_old_findings_product_scope(self):
        """Port of ``test_close_old_same_product_scan`` (exercises close_old_findings_product_scope)."""
        product = self._make_product("test2", "TestDojoCloseOldImporter2")
        eng1 = self._make_engagement("Close Old Same Product 1", product)
        eng2 = self._make_engagement("Close Old Same Product 2", product)
        eng3 = self._make_engagement("Close Old Same Product 3", product)
        many = get_unit_tests_scans_path("acunetix") / "many_findings.xml"
        one = get_unit_tests_scans_path("acunetix") / "one_finding.xml"

        r1 = self._import(eng1.id, many, scan_type=self.ACUNETIX, cof=False, cofps=True)
        self.assertEqual(4, r1["statistics"]["new"])
        self.assertEqual(0, r1["statistics"]["closed"])

        r2 = self._import(eng2.id, many, scan_type=self.ACUNETIX, cof=True, cofps=True)
        self.assertEqual(4, r2["statistics"]["new"])
        self.assertEqual(0, r2["statistics"]["closed"])

        r3 = self._import(eng3.id, one, scan_type=self.ACUNETIX, cof=True, cofps=True)
        self.assertEqual(1, r3["statistics"]["new"])
        self.assertEqual(8, r3["statistics"]["closed"])

    def test_close_old_findings_product_scope_matching_unique_id(self):
        """Port of ``test_close_old_same_product_scan_matching_with_unique_id_from_tool``."""
        product = self._make_product("test2", "TestDojoCloseOldImporter3")
        eng1 = self._make_engagement("Close Old Same Product 1", product)
        eng2 = self._make_engagement("Close Old Same Product 2", product)
        eng3 = self._make_engagement("Close Old Same Product 3", product)
        semgrep = get_unit_tests_scans_path("semgrep")

        r1 = self._import(eng1.id, semgrep / "close_old_findings_report_line31.json",
                          scan_type=self.SEMGREP, cof=False, cofps=True)
        self.assertEqual(1, r1["statistics"]["new"])
        self.assertEqual(0, r1["statistics"]["closed"])

        r2 = self._import(eng2.id, semgrep / "close_old_findings_report_second_run_line24.json",
                          scan_type=self.SEMGREP, cof=True, cofps=True)
        self.assertEqual(1, r2["statistics"]["new"])
        self.assertEqual(0, r2["statistics"]["closed"])

        r3 = self._import(eng3.id, semgrep / "close_old_findings_report_third_run_different_unique_id.json",
                          scan_type=self.SEMGREP, cof=True, cofps=True)
        self.assertEqual(1, r3["statistics"]["new"])
        self.assertEqual(1, r3["statistics"]["closed"])

    def test_close_old_closes_risk_accepted_findings(self):
        """Port of ``test_close_old_closes_risk_accepted_findings`` (close_old removes risk acceptance)."""
        import dojo.risk_acceptance.helper as ra_helper  # noqa: PLC0415

        product = self._make_product("closeold_risk", "TestCloseOldRiskAccepted")
        product.enable_simple_risk_acceptance = True
        product.save()
        engagement = self._make_engagement("Close Old Risk Accepted", product)
        many = get_unit_tests_scans_path("acunetix") / "many_findings.xml"
        one = get_unit_tests_scans_path("acunetix") / "one_finding.xml"

        r1 = self._import(engagement.id, many, scan_type=self.ACUNETIX, cof=False)
        self.assertEqual(4, r1["statistics"]["new"])
        self.assertEqual(0, r1["statistics"]["closed"])

        finding_to_accept = Test.objects.get(id=r1["test"]).finding_set.first()
        ra_helper.simple_risk_accept(self.admin, finding_to_accept)
        finding_to_accept.refresh_from_db()
        self.assertTrue(finding_to_accept.risk_accepted)
        self.assertFalse(finding_to_accept.active)

        r2 = self._import(engagement.id, one, scan_type=self.ACUNETIX, cof=True)
        self.assertEqual(1, r2["statistics"]["new"])
        self.assertGreaterEqual(r2["statistics"]["closed"], 3)

        finding_to_accept.refresh_from_db()
        self.assertTrue(finding_to_accept.is_mitigated, "Risk-accepted finding should be mitigated when fixed")
        self.assertFalse(finding_to_accept.risk_accepted, "Risk acceptance should be removed when fixed")
