import datetime

from django.test import TestCase
from django.utils import timezone

from dojo.finding.api.filters import ApiFindingFilter
from dojo.finding.ui.filters import FindingFilterHelper
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
)


def _make_finding(title, mitigation, product, reporter):
    test_type, _ = Test_Type.objects.get_or_create(name="Unit Test")
    engagement = Engagement.objects.create(
        name="Test Engagement",
        product=product,
        target_start=timezone.now().date(),
        target_end=(timezone.now() + datetime.timedelta(days=1)).date(),
    )
    test = Test.objects.create(
        engagement=engagement,
        test_type=test_type,
        target_start=timezone.now(),
        target_end=timezone.now() + datetime.timedelta(hours=1),
    )
    return Finding.objects.create(
        title=title,
        test=test,
        severity="Medium",
        mitigation=mitigation,
        reporter=reporter,
        verified=True,
        active=True,
    )


class MitigationFilterTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.reporter = Dojo_User.objects.create_user(
            username="mitigation-filter-api",
            email="mitigation-filter-api@example.com",
            password="password123",  # noqa: S106
        )
        prod_type = Product_Type.objects.create(name="Test Type")
        product = Product.objects.create(
            name="Test Product",
            description="Test Product",
            prod_type=prod_type,
        )
        cls.finding_with_mitigation = _make_finding("Finding A", "apply patch", product, cls.reporter)
        cls.finding_upper_mitigation = _make_finding("Finding D", "APPLY PATCH", product, cls.reporter)
        cls.finding_whitespace_mitigation = _make_finding("Finding E", "   ", product, cls.reporter)
        cls.finding_null_mitigation = _make_finding("Finding B", None, product, cls.reporter)
        cls.finding_empty_mitigation = _make_finding("Finding C", "", product, cls.reporter)

    def _api_filter(self, params):
        qs = Finding.objects.filter(
            title__in=["Finding A", "Finding B", "Finding C", "Finding D", "Finding E"],
        )
        f = ApiFindingFilter(params, queryset=qs)
        return set(f.qs.values_list("id", flat=True))

    # --- mitigation icontains ---

    def test_mitigation_icontains_lowercase(self):
        # Substring match: "patch" should hit "apply patch" and "APPLY PATCH"
        result = self._api_filter({"mitigation": "patch"})
        self.assertIn(self.finding_with_mitigation.id, result)
        self.assertIn(self.finding_upper_mitigation.id, result)
        self.assertNotIn(self.finding_null_mitigation.id, result)
        self.assertNotIn(self.finding_empty_mitigation.id, result)

    def test_mitigation_icontains_uppercase(self):
        # Case-insensitive: uppercase query also matches lowercase stored value
        result = self._api_filter({"mitigation": "PATCH"})
        self.assertIn(self.finding_with_mitigation.id, result)
        self.assertIn(self.finding_upper_mitigation.id, result)

    def test_mitigation_icontains_no_match(self):
        result = self._api_filter({"mitigation": "ZZZNOMATCH"})
        self.assertEqual(result, set())

    def test_mitigation_icontains_partial(self):
        # Partial substring match
        result = self._api_filter({"mitigation": "apply"})
        self.assertIn(self.finding_with_mitigation.id, result)
        self.assertIn(self.finding_upper_mitigation.id, result)
        self.assertNotIn(self.finding_null_mitigation.id, result)
        self.assertNotIn(self.finding_empty_mitigation.id, result)

    # --- mitigation_available=true ---

    def test_mitigation_available_true(self):
        # Returns only findings with non-null, non-empty mitigation
        result = self._api_filter({"mitigation_available": "true"})
        self.assertIn(self.finding_with_mitigation.id, result)
        self.assertIn(self.finding_upper_mitigation.id, result)
        # Whitespace-only is NOT null and NOT empty string — current impl includes it
        self.assertIn(self.finding_whitespace_mitigation.id, result)
        self.assertNotIn(self.finding_null_mitigation.id, result)
        self.assertNotIn(self.finding_empty_mitigation.id, result)

    # --- mitigation_available=false ---

    def test_mitigation_available_false(self):
        # Returns findings where mitigation is null OR empty string
        result = self._api_filter({"mitigation_available": "false"})
        self.assertIn(self.finding_null_mitigation.id, result)
        self.assertIn(self.finding_empty_mitigation.id, result)
        self.assertNotIn(self.finding_with_mitigation.id, result)
        self.assertNotIn(self.finding_upper_mitigation.id, result)

    def test_mitigation_available_false_handles_null(self):
        # NULL mitigation is explicitly captured by the false branch
        result = self._api_filter({"mitigation_available": "false"})
        self.assertIn(self.finding_null_mitigation.id, result)

    def test_mitigation_available_false_handles_empty_string(self):
        # Empty-string mitigation is explicitly captured by the false branch
        result = self._api_filter({"mitigation_available": "false"})
        self.assertIn(self.finding_empty_mitigation.id, result)

    def test_mitigation_available_false_excludes_whitespace(self):
        # Whitespace-only mitigation ("   ") is NOT null and NOT empty-string,
        # so the false branch does NOT include it — document current behavior.
        result = self._api_filter({"mitigation_available": "false"})
        self.assertNotIn(self.finding_whitespace_mitigation.id, result)

    # --- no filter parameter ---

    def test_no_filter_returns_full_set(self):
        # Baseline: no params → all five findings returned
        result = self._api_filter({})
        expected = {
            self.finding_with_mitigation.id,
            self.finding_upper_mitigation.id,
            self.finding_whitespace_mitigation.id,
            self.finding_null_mitigation.id,
            self.finding_empty_mitigation.id,
        }
        self.assertEqual(result, expected)

    # --- combined filters (intersection) ---

    def test_combined_mitigation_text_and_available_true(self):
        # "patch" icontains AND mitigation_available=true → only the two "patch" findings
        result = self._api_filter({"mitigation": "patch", "mitigation_available": "true"})
        self.assertEqual(
            result,
            {self.finding_with_mitigation.id, self.finding_upper_mitigation.id},
        )

    def test_combined_mitigation_text_and_available_false(self):
        # text filter AND mitigation_available=false → empty: false branch returns null/empty,
        # icontains on null/empty returns nothing matching "patch"
        result = self._api_filter({"mitigation": "patch", "mitigation_available": "false"})
        self.assertEqual(result, set())


class MitigationUIFilterTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.reporter = Dojo_User.objects.create_user(
            username="mitigation-filter-ui",
            email="mitigation-filter-ui@example.com",
            password="password123",  # noqa: S106
        )
        prod_type = Product_Type.objects.create(name="UI Test Type")
        product = Product.objects.create(
            name="UI Test Product",
            description="UI Test Product",
            prod_type=prod_type,
        )
        cls.finding_with_mitigation = _make_finding("UI Finding A", "upgrade to v2", product, cls.reporter)
        cls.finding_whitespace_mitigation = _make_finding("UI Finding D", "  ", product, cls.reporter)
        cls.finding_null_mitigation = _make_finding("UI Finding B", None, product, cls.reporter)
        cls.finding_empty_mitigation = _make_finding("UI Finding C", "", product, cls.reporter)

    def _ui_filter(self, params):
        qs = Finding.objects.filter(
            title__in=["UI Finding A", "UI Finding B", "UI Finding C", "UI Finding D"],
        )
        f = FindingFilterHelper(params, queryset=qs)
        return set(f.qs.values_list("id", flat=True))

    def test_mitigation_available_true(self):
        # True branch: excludes null and empty string; whitespace-only is included
        result = self._ui_filter({"mitigation_available": "true"})
        self.assertIn(self.finding_with_mitigation.id, result)
        self.assertIn(self.finding_whitespace_mitigation.id, result)
        self.assertNotIn(self.finding_null_mitigation.id, result)
        self.assertNotIn(self.finding_empty_mitigation.id, result)

    def test_mitigation_available_false(self):
        # False branch: returns null and empty string, excludes non-empty
        result = self._ui_filter({"mitigation_available": "false"})
        self.assertIn(self.finding_null_mitigation.id, result)
        self.assertIn(self.finding_empty_mitigation.id, result)
        self.assertNotIn(self.finding_with_mitigation.id, result)
        # Whitespace-only is not null/empty → not in false branch
        self.assertNotIn(self.finding_whitespace_mitigation.id, result)

    def test_no_filter_returns_full_set(self):
        result = self._ui_filter({})
        expected = {
            self.finding_with_mitigation.id,
            self.finding_whitespace_mitigation.id,
            self.finding_null_mitigation.id,
            self.finding_empty_mitigation.id,
        }
        self.assertEqual(result, expected)
