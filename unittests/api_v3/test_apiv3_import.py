"""
Import equivalence tests for API v3 (§4.13, §6 OS1).

The consolidated ``POST /import`` (import/reimport/auto) must reproduce the v2 endpoints' DB state
for identical payloads, including ``close_old_findings``. Both paths run in the shared test
transaction so DB-state assertions are exact.

``TestApiV3ImportAuthz`` covers the other half: auto mode dispatches on the numeric ``engagement``,
so the permission check has to resolve that same target rather than the name fields alone.
"""
from __future__ import annotations

import datetime
from collections import Counter
from unittest.mock import patch

from django.contrib.auth.models import Permission
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse

from dojo.importers.auto_create_context import AutoCreateContextManager
from dojo.models import Dojo_User, Engagement, Finding, Product, Product_Type, Test, Test_Type, User

from .base import ApiV3TestCase

_ZAP = "ZAP Scan"
_GENERIC = "Generic Findings Import"


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
            mode="auto", asset_name="v3 Auto Product", engagement_name="v3 Auto Eng",
            organization_name="v3 Auto PT", auto_create_context="true",
        )
        self.assertEqual("import", created["mode_resolved"])
        first_test = created["test"]["id"]
        self.assertTrue(Test.objects.filter(pk=first_test).exists())

        # Auto again with the same identifiers resolves the existing test -> reimport.
        reused = self._v3_import(
            mode="auto", asset_name="v3 Auto Product", engagement_name="v3 Auto Eng",
            organization_name="v3 Auto PT", auto_create_context="true",
        )
        self.assertEqual("reimport", reused["mode_resolved"])
        self.assertEqual(first_test, reused["test"]["id"])


class TestApiV3ImportAuthz(ApiV3TestCase):

    """Auto mode must not import into an engagement the caller cannot import to."""

    def setUp(self):
        super().setUp()
        product = Product.objects.create(
            name="authz victim product",
            prod_type=Product_Type.objects.create(name="authz victim org"),
            description="victim",
        )
        self.engagement = Engagement.objects.create(
            name="authz victim engagement", product=product,
            target_start=datetime.date(2026, 1, 1), target_end=datetime.date(2026, 2, 1),
        )
        # Holds the self-service product-type add permission and nothing else, so the name-based
        # auto-create check passes while the engagement stays out of reach.
        self.outsider = User.objects.create(username="authz outsider", is_active=True)
        self.outsider.user_permissions.add(Permission.objects.get(codename="add_product_type"))
        self.outsider = User.objects.get(pk=self.outsider.pk)

    def _post(self):
        scan = SimpleUploadedFile(
            "scan.json",
            b'{"findings":[{"title":"injected","severity":"High","description":"x"}]}',
            content_type="application/json",
        )
        return self.token_client(user=self.outsider).post(self.v3_url("import"), {
            "scan_type": _GENERIC,
            "mode": "auto",
            "auto_create_context": "true",
            "asset_name": "authz unused name",
            "organization_name": "authz unused org",
            "engagement_name": "authz unused engagement",
            "engagement": self.engagement.id,
            "file": scan,
        }, format="multipart")

    def test_auto_mode_rejects_unauthorized_engagement_id(self):
        response = self._post()
        self.assertEqual(403, response.status_code, response.content[:400])
        self.assertFalse(Test.objects.filter(engagement=self.engagement).exists())

    def test_auto_mode_rejects_unauthorized_engagement_id_with_existing_test(self):
        # With a matching test already there, auto resolves to reimport, which also closes the
        # engagement's active findings. Same denial.
        test = Test.objects.create(
            engagement=self.engagement,
            test_type=Test_Type.objects.get_or_create(name=_GENERIC)[0],
            scan_type=_GENERIC,
            target_start=datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC),
            target_end=datetime.datetime(2026, 2, 1, tzinfo=datetime.UTC),
        )
        finding = Finding.objects.create(
            test=test, title="existing", severity="High", description="x",
            active=True, verified=False, reporter=self.admin,
        )

        response = self._post()

        self.assertEqual(403, response.status_code, response.content[:400])
        finding.refresh_from_db()
        self.assertTrue(finding.active)
        self.assertEqual(1, Finding.objects.filter(test__engagement=self.engagement).count())

    def _post_import_mode(self, user=None, **overrides):
        scan = SimpleUploadedFile(
            "scan.json",
            b'{"findings":[{"title":"injected","severity":"High","description":"x"}]}',
            content_type="application/json",
        )
        payload = {
            "scan_type": _GENERIC,
            "mode": "import",
            "auto_create_context": "true",
            "asset_name": self.engagement.product.name,
            "organization_name": self.engagement.product.prod_type.name,
            "engagement_name": "authz probe engagement",
            "file": scan,
        }
        payload.update(overrides)
        return self.token_client(user=user or self.outsider).post(
            self.v3_url("import"), payload, format="multipart",
        )

    def test_import_mode_rejects_existing_asset_by_name(self):
        response = self._post_import_mode()
        self.assertEqual(403, response.status_code, response.content[:400])
        self.assertFalse(
            Engagement.objects.filter(product=self.engagement.product, name="authz probe engagement").exists(),
        )

    def test_import_mode_rejects_close_old_findings_on_existing_asset(self):
        test = Test.objects.create(
            engagement=self.engagement,
            test_type=Test_Type.objects.get_or_create(name=_GENERIC)[0],
            scan_type=_GENERIC,
            target_start=datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC),
            target_end=datetime.datetime(2026, 2, 1, tzinfo=datetime.UTC),
        )
        finding = Finding.objects.create(
            test=test, title="existing", severity="High", description="x",
            active=True, verified=False, reporter=self.admin,
        )

        response = self._post_import_mode(
            close_old_findings="true", close_old_findings_product_scope="true",
        )

        self.assertEqual(403, response.status_code, response.content[:400])
        finding.refresh_from_db()
        self.assertTrue(finding.active)
        self.assertFalse(finding.is_mitigated)

    def test_import_mode_still_allows_auto_create_of_a_new_asset(self):
        response = self._post_import_mode(
            asset_name="authz brand new asset",
            organization_name="authz brand new org",
        )
        self.assertEqual(200, response.status_code, response.content[:400])

    def test_rejects_new_asset_in_existing_org(self):
        org = self.engagement.product.prod_type
        for mode in ("import", "auto"):
            with self.subTest(mode=mode):
                response = self._post_import_mode(mode=mode, asset_name=f"authz planted {mode}")
                self.assertEqual(403, response.status_code, response.content[:400])
                self.assertFalse(Product.objects.filter(prod_type=org, name=f"authz planted {mode}").exists())

    def test_org_member_can_auto_create_asset_in_their_org(self):
        member = Dojo_User.objects.create(username="authz org member", is_active=True)
        self.engagement.product.prod_type.authorized_users.add(member)
        for mode in ("import", "auto"):
            with self.subTest(mode=mode):
                response = self._post_import_mode(user=member, mode=mode, asset_name=f"authz member {mode}")
                self.assertEqual(200, response.status_code, response.content[:400])


class TestApiV3ImportReportTool(ApiV3TestCase):

    """
    A reimport by title lands in the test of the report's tool, reading the report for it once.

    One scan type can carry several tools (GitLab SAST: njsscan, Find Security Bugs), and the title
    lookup narrows to the report's tool. The route's permission check and ``auto_import_scan``
    resolve the target on the request's one ``AutoCreateContextManager``, so the report is read for
    its tool once per request, not once by each.
    """

    _GITLAB_SAST = "GitLab SAST Report"

    def _reimport_by_title(self, report: str) -> dict:
        from unittests.dojo_test_case import get_unit_tests_scans_path  # noqa: PLC0415

        with (get_unit_tests_scans_path("gitlab_sast") / report).open(encoding="utf-8") as scan:
            response = self.client.post(self.v3_url("import"), {
                "scan_type": self._GITLAB_SAST,
                "mode": "reimport",
                "file": scan,
                "asset_name": "v3 report tool product",
                "engagement_name": "v3 report tool engagement",
                "organization_name": "v3 report tool org",
                "test_title": "pipeline sast",
                "auto_create_context": "true",
            }, format="multipart")
        self.assertEqual(200, response.status_code, response.content[:1000])
        return response.json()

    def test_second_tool_gets_its_own_test_and_its_report_is_read_once(self):
        njsscan_test = self._reimport_by_title("gl-sast-report-confidence_v15.json")["test"]["id"]

        read = AutoCreateContextManager._read_report_test_type_names
        with patch.object(AutoCreateContextManager, "_read_report_test_type_names", side_effect=read) as spy:
            fsb = self._reimport_by_title("gl-sast-report-cwe_v15.json")

        self.assertEqual("import", fsb["mode_resolved"])
        self.assertNotEqual(njsscan_test, fsb["test"]["id"])
        self.assertEqual(
            "Find Security Bugs Scan (GitLab SAST Report)", Test.objects.get(pk=fsb["test"]["id"]).test_type.name,
        )
        self.assertEqual(
            1, spy.call_count,
            f"the report was read for its tool {spy.call_count} times in one request: {spy.call_args_list}",
        )
