"""
Dual-endpoint adapter for running the v2 import/reimport test corpus against API v3 (§10 port,
backlog priority 1).

The v2 corpus (``unittests/test_import_reimport.py``) drives its scenarios through two helper
methods -- ``import_scan_with_params`` / ``reimport_scan_with_params`` -- and inspects results with
the shared ``DojoAPITestCase`` DB/finding helpers. This module supplies a mixin that overrides ONLY
those two helpers so the *identical* scenarios and assertions run against the consolidated
``POST /api/v3-alpha/import`` endpoint instead of the v2 ``importscan``/``reimportscan`` endpoints.

Mapping performed by the shim (v2 wire -> v3 wire, D11 §12):
  * ``product_name``       -> ``asset_name``
  * ``product_type_name``  -> ``organization_name``
  * import vs reimport     -> a single POST with ``mode=import|reimport|auto``
    (``reimport`` with no ``test`` id and the auto-create fields resolves to ``mode=auto``)
  * v3 response ``{mode_resolved, test:{id,name}, statistics:{...}, close_old_findings}``
    -> the v2-shaped dict the corpus reads: ``{"test": <test_id>, ...}``.

The endpoint→location count redirect (``db_endpoint_count`` / ``db_endpoint_status_count``) is
inherited unchanged from ``ImportReimportTestAPI`` -- under ``V3_FEATURE_LOCATIONS=True`` it already
delegates to the location counters, exactly as this shim needs.

This file is intentionally NOT named ``test_*`` so Django's ``test*.py`` discovery does not load it
as a test module; it only holds the reusable mixin.
"""
from __future__ import annotations

from pathlib import Path
from unittest import skipUnless

from django.conf import settings

from dojo.utils import get_system_setting


def _bool_str(value: object) -> str:
    """Render a Python bool (or truthy value) the way the v3 multipart form expects it."""
    return "true" if bool(value) else "false"


@skipUnless(
    settings.V3_FEATURE_LOCATIONS,
    "API v3 import endpoint is mounted only when V3_FEATURE_LOCATIONS is enabled (D5); the CI "
    "unit-test matrix runs a flag-off leg where /api/v3-alpha/ does not exist. Guarding the shim "
    "skips every corpus test that mixes it in (they hit POST /api/v3-alpha/import).",
)
class ApiV3ImportShim:

    """
    Overrides ``import_scan_with_params`` / ``reimport_scan_with_params`` to hit ``POST /import``.

    Mix in *before* the v2 corpus class so these overrides win in the MRO, e.g.::

        class Corpus(ApiV3ImportShim, ImportReimportTestAPI):
            ...
    """

    # --- v3 URL helper (mirrors unittests.api_v3.base.ApiV3TestCase.v3_url) ------------------
    def v3_url(self, path: str = "") -> str:
        prefix = get_system_setting("url_prefix")
        return f"/{prefix}{settings.API_V3_URL_PREFIX}/{path.lstrip('/')}"

    # --- core POST + response translation ---------------------------------------------------
    def _post_v3_import(self, payload: dict, filename, *, expected: int) -> dict:
        with Path(filename).open(encoding="utf-8") as scan_file:
            payload = {**payload, "file": scan_file}
            response = self.client.post(self.v3_url("import"), payload, format="multipart")
        self.assertEqual(expected, response.status_code, response.content[:1500])
        body = response.json()
        if expected not in {200, 201}:
            # error path: hand the raw problem+json back to the caller unchanged
            return body
        # Translate the v3 envelope into the v2-shaped dict the corpus assertions read.
        return {
            "test": body["test"]["id"],
            "test_id": body["test"]["id"],
            "mode_resolved": body.get("mode_resolved"),
            "statistics": body.get("statistics"),
            "close_old_findings": body.get("close_old_findings"),
        }

    def _skip_unsupported(self, *, push_to_jira, group_by=None, endpoint_to_add=None) -> None:
        if push_to_jira is not None:
            self.skipTest("push_to_jira is deferred to the JIRA work stream (§4.13 / §12).")
        if group_by is not None:
            self.skipTest("group_by is not on the v3 ImportForm (no ported scenario requires it; §12).")
        if endpoint_to_add is not None:
            self.skipTest("endpoint_to_add / legacy Endpoint wiring is out of v3 scope (§4.13).")

    def _base_payload(self, *, mode, scan_type, minimum_severity) -> dict:
        # version is sent unconditionally by the v2 helpers; keep parity.
        return {"scan_type": scan_type, "mode": mode, "version": "1.0.1", "minimum_severity": minimum_severity}

    @staticmethod
    def _apply_common(payload: dict, *, active, verified, close_old_findings, scan_date, service, tags,
                      test_title, product_name, product_type_name, engagement_name, auto_create_context) -> None:
        if active is not None:
            payload["active"] = _bool_str(active)
        if verified is not None:
            payload["verified"] = _bool_str(verified)
        if close_old_findings is not None:
            payload["close_old_findings"] = _bool_str(close_old_findings)
        if scan_date is not None:
            payload["scan_date"] = scan_date
        if service is not None:
            payload["service"] = service
        if tags is not None:
            payload["tags"] = ",".join(tags) if isinstance(tags, (list, tuple)) else tags
        if test_title is not None:
            payload["test_title"] = test_title
        if product_name:
            payload["asset_name"] = product_name
        if product_type_name:
            payload["organization_name"] = product_type_name
        if engagement_name:
            payload["engagement_name"] = engagement_name
        if auto_create_context:
            payload["auto_create_context"] = _bool_str(auto_create_context)

    # --- overridden corpus helpers ----------------------------------------------------------
    def import_scan_with_params(self, filename, scan_type="ZAP Scan", engagement=1, minimum_severity="Low", *,
                                active=True, verified=False, push_to_jira=None, endpoint_to_add=None, tags=None,
                                close_old_findings=None, group_by=None, engagement_name=None, product_name=None,
                                product_type_name=None, auto_create_context=None, expected_http_status_code=201,
                                test_title=None, scan_date=None, service=None, force_active=True, force_verified=True):
        self._skip_unsupported(push_to_jira=push_to_jira, group_by=group_by, endpoint_to_add=endpoint_to_add)
        mode = "auto" if auto_create_context else "import"
        payload = self._base_payload(mode=mode, scan_type=scan_type, minimum_severity=minimum_severity)
        if mode == "import" and engagement is not None:
            payload["engagement"] = engagement
        self._apply_common(
            payload, active=active, verified=verified, close_old_findings=close_old_findings,
            scan_date=scan_date, service=service, tags=tags, test_title=test_title,
            product_name=product_name, product_type_name=product_type_name,
            engagement_name=engagement_name, auto_create_context=auto_create_context,
        )
        expected = 200 if expected_http_status_code == 201 else expected_http_status_code
        return self._post_v3_import(payload, filename, expected=expected)

    def reimport_scan_with_params(self, test_id, filename, scan_type="ZAP Scan", engagement=1, minimum_severity="Low", *,
                                  active=True, verified=False, push_to_jira=None, tags=None, close_old_findings=None,
                                  group_by=None, engagement_name=None, scan_date=None, service=None, product_name=None,
                                  product_type_name=None, auto_create_context=None, expected_http_status_code=201,
                                  test_title=None):
        self._skip_unsupported(push_to_jira=push_to_jira, group_by=group_by)
        mode = "reimport" if test_id is not None else "auto"
        payload = self._base_payload(mode=mode, scan_type=scan_type, minimum_severity=minimum_severity)
        if test_id is not None:
            payload["test"] = test_id
        elif engagement is not None and not product_name:
            # auto-create/resolve path: honour an explicit engagement id only when the caller
            # is NOT resolving by asset/engagement name. When asset_name is supplied the name-based
            # lookup is authoritative (mirrors the v2 serializer, which ignores the numeric default);
            # sending both a mismatched engagement id and asset_name trips the v3 consistency check.
            payload["engagement"] = engagement
        self._apply_common(
            payload, active=active, verified=verified, close_old_findings=close_old_findings,
            scan_date=scan_date, service=service, tags=tags, test_title=test_title,
            product_name=product_name, product_type_name=product_type_name,
            engagement_name=engagement_name, auto_create_context=auto_create_context,
        )
        expected = 200 if expected_http_status_code == 201 else expected_http_status_code
        return self._post_v3_import(payload, filename, expected=expected)
