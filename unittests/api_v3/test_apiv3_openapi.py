"""
OpenAPI schema-generation guard for API v3 (§4.1, §6 OS2).

A CI-facing unit test asserting ``api_v3.get_openapi_schema()`` renders and contains the expected
paths, components, per-resource tags and the alpha banner. This guards against a schema-generation
regression (a broken schema silently breaks client codegen and the interactive docs).
"""
from __future__ import annotations

from django.conf import settings
from django.test import SimpleTestCase

from dojo.api_v3.api import api_v3


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
        paths = set(self.schema["paths"])
        for suffix in ("/findings", "/findings/{finding_id}", "/import"):
            self.assertTrue(
                any(p.endswith(suffix) for p in paths),
                f"missing a path ending in {suffix}; have {sorted(paths)}",
            )

    def test_expected_components_present(self):
        components = set(self.schema["components"]["schemas"])
        for expected in ("Ref", "FindingSlim", "FindingDetail"):
            self.assertIn(expected, components, f"missing component {expected}")

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
        self.assertLessEqual({"findings", "import"}, tags, f"tags found: {sorted(tags)}")
