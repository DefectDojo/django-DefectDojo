"""
Scalar reference page (§12: npm-at-image-build — the bundle is a yarn-managed static asset,
no CDN at runtime, no vendored blob in git).

The page is an HTML shell: the only executable content is the locally-served Scalar bundle,
installed by the existing components yarn step (exact pin in ``components/package.json``,
integrity via ``components/yarn.lock``) and exposed through ``STATICFILES_DIRS`` →
``components/node_modules``. These tests pin that contract: the static script URL, no CDN/SRI
remnants, the exact-pin in package.json, and the schema/docs URLs resolved by name (so the beta
URL move carries them along).
"""
from __future__ import annotations

import json
from pathlib import Path

from django.templatetags.static import static
from django.urls import reverse

from dojo.api_v3.api import api_v3
from dojo.api_v3.reference_docs import SCALAR_STATIC_PATH

from .base import ApiV3TestCase


class TestApiV3ScalarReference(ApiV3TestCase):

    def _get(self):
        return self.anonymous_client().get(reverse("api_v3_reference"))

    def test_page_serves_locally_hosted_bundle(self):
        response = self._get()
        self.assertEqual(200, response.status_code)
        html = response.content.decode()
        self.assertIn(f'<script src="{static(SCALAR_STATIC_PATH)}"></script>', html)
        # The npm-at-build decision: no runtime CDN, so no CDN host and no SRI attribute.
        self.assertNotIn("cdn.jsdelivr.net", html)
        self.assertNotIn("integrity=", html)

    def test_bundle_is_exact_pinned_in_components_package_json(self):
        # Integrity is enforced by yarn (exact pin + lockfile hashes) at image build, not by a
        # browser SRI attribute at runtime — so the pin itself is the contract to guard.
        package_json = Path(__file__).parents[2] / "components" / "package.json"
        deps = json.loads(package_json.read_text())["dependencies"]
        version = deps["@scalar/api-reference"]
        self.assertRegex(version, r"^\d+\.\d+\.\d+$", "Scalar must be pinned exactly (no ^/~/latest)")

    def test_page_points_at_v3_schema_and_swagger_fallback(self):
        html = self._get().content.decode()
        self.assertIn(f'data-url="{reverse("api_v3:openapi-json")}"', html)
        # Swagger (framework-bundled assets) remains linked for noscript.
        self.assertIn(reverse("api_v3:openapi-view"), html)

    def test_reference_page_is_not_an_api_operation(self):
        # A plain Django view: it must NOT appear in the OpenAPI schema (and therefore places no
        # obligations on the authz/query completeness gates, which walk the schema).
        paths = api_v3.get_openapi_schema()["paths"]
        self.assertFalse(any(p.endswith("/reference") for p in paths))
