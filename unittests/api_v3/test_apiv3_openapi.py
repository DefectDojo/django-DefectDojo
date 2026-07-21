"""
OpenAPI schema-generation guard for API v3 (§4.1, §6 OS2).

A CI-facing unit test asserting ``api_v3.get_openapi_schema()`` renders and contains the expected
paths, components, per-resource tags and the alpha banner. This guards against a schema-generation
regression (a broken schema silently breaks client codegen and the interactive docs).
"""
from __future__ import annotations

from unittest import skipUnless

from django.conf import settings
from django.test import SimpleTestCase

from dojo.api_v3.api import api_v3


@skipUnless(
    settings.V3_FEATURE_LOCATIONS,
    "api_v3.get_openapi_schema() resolves the mounted namespace, which does not exist when "
    "V3_FEATURE_LOCATIONS is off (D5); the CI unit-test matrix runs a flag-off leg.",
)
class TestApiV3OpenApi(SimpleTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.schema = api_v3.get_openapi_schema()

    def test_info_version_and_alpha_banner(self):
        self.assertEqual(settings.API_V3_VERSION, self.schema["info"]["version"])
        self.assertIn("alpha", self.schema["info"]["description"].lower())

    def test_expected_paths_present(self):
        # Paths carry the mount prefix (/api/v3-alpha/...); assert on the operation suffix.
        # Per D11 the wire paths are /organizations and /assets (not /product_types, /products).
        paths = set(self.schema["paths"])
        for suffix in (
            "/findings", "/findings/{finding_id}", "/import",
            "/organizations", "/organizations/{organization_id}",
            "/assets", "/assets/{asset_id}", "/assets/{asset_id}/locations",
        ):
            self.assertTrue(
                any(p.endswith(suffix) for p in paths),
                f"missing a path ending in {suffix}; have {sorted(paths)}",
            )
        # D11 all-or-nothing guard: no legacy product/product_type token in any wire path segment.
        offenders = [p for p in paths if "product" in p.lower()]
        self.assertEqual([], offenders, f"legacy product token in wire paths: {offenders}")

    def test_expected_components_present(self):
        # Per D11 the schema classes are Asset*/Organization* (not Product*/ProductType*).
        components = set(self.schema["components"]["schemas"])
        for expected in ("Ref", "FindingSlim", "FindingDetail", "AssetSlim", "OrganizationSlim"):
            self.assertIn(expected, components, f"missing component {expected}")
        # D11 guard: no legacy product token in component *schema names*. (The scalar model-column
        # properties critical_product/key_product are the deliberate documented residual -- D11
        # excludes DB columns -- so component *property* names are intentionally not checked; §12.)
        name_offenders = [c for c in components if "product" in c.lower()]
        self.assertEqual([], name_offenders, f"legacy product token in component names: {name_offenders}")

    def test_ref_component_is_closed_shape(self):
        ref = self.schema["components"]["schemas"]["Ref"]
        self.assertEqual({"id", "name"}, set(ref["properties"]))

    def test_per_resource_tags(self):
        tags = {
            tag
            for path in self.schema["paths"].values()
            for operation in path.values()
            for tag in operation.get("tags", [])
        }
        self.assertLessEqual(
            {"findings", "import", "organizations", "assets"}, tags, f"tags found: {sorted(tags)}",
        )
        # D11 guard: no legacy product/product_type token in any OpenAPI tag.
        tag_offenders = [t for t in tags if "product" in t.lower()]
        self.assertEqual([], tag_offenders, f"legacy product token in tags: {tag_offenders}")
