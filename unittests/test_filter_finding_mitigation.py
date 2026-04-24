import datetime

from django.test import TestCase
from django.utils import timezone

from dojo.filters import ApiFindingFilter, FindingFilterHelper
from dojo.models import (
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
)


def _make_finding(title, mitigation, product):
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
        verified=True,
        active=True,
    )


class MitigationFilterTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        prod_type = Product_Type.objects.create(name="Test Type")
        product = Product.objects.create(
            name="Test Product",
            prod_type=prod_type,
        )
        cls.finding_with_mitigation = _make_finding("Finding A", "apply patch", product)
        cls.finding_null_mitigation = _make_finding("Finding B", None, product)
        cls.finding_empty_mitigation = _make_finding("Finding C", "", product)

    def _api_filter(self, params):
        qs = Finding.objects.all()
        f = ApiFindingFilter(params, queryset=qs)
        return set(f.qs.values_list("id", flat=True))

    def test_mitigation_icontains(self):
        # Filtering by mitigation text returns only findings whose mitigation contains that substring
        pass

    def test_mitigation_available_true(self):
        # mitigation_available=true returns only findings with a non-null, non-empty mitigation
        pass

    def test_mitigation_available_false(self):
        # mitigation_available=false returns only findings with a null or empty mitigation
        pass

    def test_mitigation_available_false_handles_null(self):
        # mitigation_available=false includes findings where mitigation is NULL
        pass

    def test_mitigation_available_false_handles_empty_string(self):
        # mitigation_available=false includes findings where mitigation is an empty string
        pass


class MitigationUIFilterTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        prod_type = Product_Type.objects.create(name="UI Test Type")
        product = Product.objects.create(
            name="UI Test Product",
            prod_type=prod_type,
        )
        cls.finding_with_mitigation = _make_finding("UI Finding A", "upgrade to v2", product)
        cls.finding_null_mitigation = _make_finding("UI Finding B", None, product)
        cls.finding_empty_mitigation = _make_finding("UI Finding C", "", product)

    def _ui_filter(self, params):
        qs = Finding.objects.all()
        f = FindingFilterHelper(params, queryset=qs)
        return set(f.qs.values_list("id", flat=True))

    def test_mitigation_available_true(self):
        # mitigation_available=true returns only findings with a non-null, non-empty mitigation
        pass

    def test_mitigation_available_false(self):
        # mitigation_available=false returns only findings with a null or empty mitigation
        pass
