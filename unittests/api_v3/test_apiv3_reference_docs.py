"""
Scalar reference page (§12: supersedes the OS6 Scalar deferral — CDN + SRI, no vendored asset).

The page is an HTML shell: the only executable content is the version-pinned CDN bundle whose
SRI hash the browser enforces. These tests pin that contract: exact pinned URL, integrity attr,
crossorigin, and the schema/docs URLs resolved by name (so the beta URL move carries them along).
"""
from __future__ import annotations

from django.urls import reverse

from dojo.api_v3.api import api_v3
from dojo.api_v3.reference_docs import SCALAR_CDN_URL, SCALAR_SRI_HASH

from .base import ApiV3TestCase


class TestApiV3ScalarReference(ApiV3TestCase):

    def _get(self):
        return self.anonymous_client().get(reverse("api_v3_reference"))

    def test_page_serves_pinned_bundle_with_sri(self):
        response = self._get()
        self.assertEqual(200, response.status_code)
        html = response.content.decode()
        self.assertIn(SCALAR_CDN_URL, html)
        self.assertIn(f'integrity="{SCALAR_SRI_HASH}"', html)
        self.assertIn('crossorigin="anonymous"', html)
        # Version must be pinned, never floating.
        self.assertIn("@scalar/api-reference@", SCALAR_CDN_URL)
        self.assertNotIn("@latest", SCALAR_CDN_URL)

    def test_page_points_at_v3_schema_and_swagger_fallback(self):
        html = self._get().content.decode()
        self.assertIn(f'data-url="{reverse("api_v3:openapi-json")}"', html)
        # Swagger (locally-served assets) remains the offline-safe default, linked for noscript.
        self.assertIn(reverse("api_v3:openapi-view"), html)

    def test_reference_page_is_not_an_api_operation(self):
        # A plain Django view: it must NOT appear in the OpenAPI schema (and therefore places no
        # obligations on the authz/query completeness gates, which walk the schema).
        paths = api_v3.get_openapi_schema()["paths"]
        self.assertFalse(any(p.endswith("/reference") for p in paths))
