from django.utils import timezone

from dojo.models import Engagement, Finding, Product, Product_Type, Test, Test_Type
from dojo.tools.locations import LocationData
from unittests.dojo_test_case import DojoTestCase, skip_unless_v3


class TestLocationDataCodeFactory(DojoTestCase):

    def test_code_factory_identity_keys(self):
        data = LocationData.code(file_path="src/db/queries.py", line=42)
        self.assertEqual("code", data.type)
        self.assertEqual("src/db/queries.py", data.data["file_path"])
        self.assertEqual(42, data.data["line"])

    def test_code_factory_omits_unset_context(self):
        data = LocationData.code(file_path="src/db/queries.py", line=42)
        for key in ("end_line", "snippet", "source_object", "sink_object", "source_file_path", "source_line"):
            self.assertNotIn(key, data.data)

    def test_code_factory_keeps_populated_context(self):
        data = LocationData.code(
            file_path="src/db/queries.py",
            line=42,
            end_line=44,
            snippet='q = f"SELECT * FROM users"',
            source_object="user_id",
            sink_object="execute",
        )
        self.assertEqual(44, data.data["end_line"])
        self.assertEqual('q = f"SELECT * FROM users"', data.data["snippet"])
        self.assertEqual("user_id", data.data["source_object"])
        self.assertEqual("execute", data.data["sink_object"])
        self.assertNotIn("source_file_path", data.data)
        self.assertNotIn("source_line", data.data)

    def test_code_factory_line_none_is_allowed(self):
        data = LocationData.code(file_path="Dockerfile")
        self.assertEqual("Dockerfile", data.data["file_path"])
        self.assertIsNone(data.data["line"])


@skip_unless_v3
class TestGetLocationsHashSymmetry(DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        product_type = Product_Type.objects.create(name="hash symmetry type")
        product = Product.objects.create(name="hash symmetry product", description="hash symmetry", prod_type=product_type)
        engagement = Engagement.objects.create(
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        cls.test = Test.objects.create(
            engagement=engagement,
            test_type=Test_Type.objects.create(name="hash symmetry scanner"),
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    def _finding(self):
        return Finding(test=self.test, title="Hash symmetry", severity="Low")

    def test_unsaved_non_url_locations_do_not_enter_the_endpoints_ingredient(self):
        # The saved path filters references to URL locations; the unsaved path
        # must filter the same way or a finding's hash changes across save
        finding = self._finding()
        finding.unsaved_locations = [
            LocationData.dependency(purl="pkg:npm/lodash@4.17.21", purl_type="npm", name="lodash", version="4.17.21"),
        ]
        self.assertEqual("", finding.get_locations())

    def test_unsaved_url_locations_still_hash(self):
        finding = self._finding()
        finding.unsaved_locations = [
            LocationData.url(url="https://example.com/login", host="example.com", protocol="https", path="login"),
        ]
        self.assertIn("example.com", finding.get_locations())

    def test_mixed_unsaved_locations_hash_only_urls(self):
        finding = self._finding()
        finding.unsaved_locations = [
            LocationData.url(url="https://example.com/login", host="example.com", protocol="https", path="login"),
            LocationData.dependency(purl="pkg:npm/lodash@4.17.21", purl_type="npm", name="lodash", version="4.17.21"),
        ]
        value = finding.get_locations()
        self.assertIn("example.com", value)
        self.assertNotIn("lodash", value)
