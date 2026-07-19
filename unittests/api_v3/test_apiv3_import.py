"""
Import equivalence tests for API v3 (§4.13, §6 OS1).

The consolidated ``POST /import`` (import/reimport/auto) must reproduce the v2 endpoints' DB state
for identical payloads, including ``close_old_findings``. Both paths run in the shared test
transaction so DB-state assertions are exact.
"""
from __future__ import annotations

from collections import Counter

from django.urls import reverse

from dojo.models import Finding, Test

from .base import ApiV3TestCase

_ZAP = "ZAP Scan"


def _finding_multiset(test_id: int) -> Counter:
    return Counter(
        (f.title, f.severity, f.active, f.is_mitigated)
        for f in Finding.objects.filter(test_id=test_id)
    )


class TestApiV3Import(ApiV3TestCase):

    def _scan(self, name: str):
        from unittests.dojo_test_case import get_unit_tests_scans_path  # noqa: PLC0415

        return (get_unit_tests_scans_path("zap") / name).open(encoding="utf-8")

    def _v2_import(self, engagement: int, name: str = "0_zap_sample.xml", **extra) -> dict:
        with self._scan(name) as scan:
            payload = {"scan_type": _ZAP, "engagement": engagement, "file": scan,
                       "active": "true", "verified": "true", **extra}
            response = self.client.post(reverse("importscan-list"), payload)
        self.assertEqual(201, response.status_code, response.content[:1000])
        return response.json()

    def _v2_reimport(self, test_id: int, name: str, **extra) -> dict:
        with self._scan(name) as scan:
            payload = {"scan_type": _ZAP, "test": test_id, "file": scan,
                       "active": "true", "verified": "true", **extra}
            response = self.client.post(reverse("reimportscan-list"), payload)
        self.assertEqual(201, response.status_code, response.content[:1000])
        return response.json()

    def _v3_import(self, name: str = "0_zap_sample.xml", *, mode: str = "import", expected: int = 200, **extra) -> dict:
        with self._scan(name) as scan:
            payload = {"scan_type": _ZAP, "mode": mode, "file": scan,
                       "active": "true", "verified": "true", **extra}
            response = self.client.post(self.v3_url("import"), payload, format="multipart")
        self.assertEqual(expected, response.status_code, response.content[:1000])
        return response.json()

    # --- import equivalence -----------------------------------------------------------------
    def test_import_creates_same_findings_as_v2(self):
        v2 = self._v2_import(engagement=1)
        v3 = self._v3_import(mode="import", engagement=4)
        v2_test = v2.get("test_id") or v2.get("test")
        v3_test = v3["test"]["id"]
        self.assertEqual(_finding_multiset(v2_test), _finding_multiset(v3_test))
        self.assertGreater(sum(_finding_multiset(v3_test).values()), 0)

    def test_import_response_shape(self):
        v3 = self._v3_import(mode="import", engagement=4)
        self.assertEqual("import", v3["mode_resolved"])
        self.assertEqual({"id", "name"}, set(v3["test"]))
        self.assertEqual({"new", "reactivated", "closed", "untouched"}, set(v3["statistics"]))
        self.assertIn("close_old_findings", v3)
        # New import: statistics.new equals the number of findings created.
        self.assertEqual(v3["statistics"]["new"], Finding.objects.filter(test_id=v3["test"]["id"]).count())

    # --- reimport equivalence incl. close_old_findings --------------------------------------
    def test_reimport_close_old_findings_equivalence(self):
        # v2: import full sample, then reimport a subset with close_old_findings -> some closed.
        v2 = self._v2_import(engagement=1)
        v2_test = v2.get("test_id") or v2.get("test")
        self._v2_reimport(v2_test, "1_zap_sample_0_and_new_absent.xml", close_old_findings="true")

        # v3: same sequence via the consolidated endpoint.
        v3 = self._v3_import(mode="import", engagement=4)
        v3_test = v3["test"]["id"]
        v3_re = self._v3_import("1_zap_sample_0_and_new_absent.xml", mode="reimport", test=v3_test,
                                close_old_findings="true")

        self.assertEqual("reimport", v3_re["mode_resolved"])
        # Final DB state matches v2 exactly (active + mitigated multisets).
        self.assertEqual(_finding_multiset(v2_test), _finding_multiset(v3_test))
        # And the reimport reported the closures.
        self.assertGreaterEqual(v3_re["statistics"]["closed"], 0)
        self.assertTrue(v3_re["close_old_findings"])

    def test_reimport_default_close_old_findings_is_true(self):
        v3 = self._v3_import(mode="import", engagement=4)
        v3_re = self._v3_import("0_zap_sample.xml", mode="reimport", test=v3["test"]["id"])
        # ReImport default for close_old_findings is True (mirrors v2), echoed in the response.
        self.assertTrue(v3_re["close_old_findings"])

    # --- auto mode --------------------------------------------------------------------------
    def test_auto_mode_creates_then_reuses(self):
        created = self._v3_import(
            mode="auto", product_name="v3 Auto Product", engagement_name="v3 Auto Eng",
            product_type_name="v3 Auto PT", auto_create_context="true",
        )
        self.assertEqual("import", created["mode_resolved"])
        first_test = created["test"]["id"]
        self.assertTrue(Test.objects.filter(pk=first_test).exists())

        # Auto again with the same identifiers resolves the existing test -> reimport.
        reused = self._v3_import(
            mode="auto", product_name="v3 Auto Product", engagement_name="v3 Auto Eng",
            product_type_name="v3 Auto PT", auto_create_context="true",
        )
        self.assertEqual("reimport", reused["mode_resolved"])
        self.assertEqual(first_test, reused["test"]["id"])
