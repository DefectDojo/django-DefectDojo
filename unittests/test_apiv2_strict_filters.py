"""
An /api/v2 list answers 400 for a query parameter no filter declares.

django-filter ignores an undeclared key, so ``?not_a_filter=x`` (or a typo such as ``?severty=``) used
to return every row with a 200. See dojo/api_v2/strict_filters.py.
"""

import logging

import django_filters
from django import forms
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from dojo.api_v2 import strict_filters
from dojo.api_v2.strict_filters import (
    RESERVED_QUERY_PARAMS,
    UNKNOWN_QUERY_PARAMS_HEADER,
    filterset_query_params,
    register_reserved_query_params,
    reserved_query_params,
    unknown_query_params_mode,
)
from dojo.models import Engagement, Finding, Product, Product_Type, Test, Test_Type, User

from .dojo_test_case import DojoAPITestCase, DojoTestCase


@override_settings(SECURE_SSL_REDIRECT=False)
class StrictFilterListTest(DojoAPITestCase):

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create(username="strict_filters_admin", is_staff=True, is_superuser=True)
        product = Product.objects.create(
            name="Strict Filters Product",
            description="d",
            prod_type=Product_Type.objects.create(name="Strict Filters Type"),
        )
        engagement = Engagement.objects.create(
            name="Strict Filters Engagement", product=product, target_start=timezone.now(), target_end=timezone.now(),
        )
        test = Test.objects.create(
            engagement=engagement,
            test_type=Test_Type.objects.get_or_create(name="Strict Filters Scan")[0],
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        cls.findings = [
            Finding.objects.create(test=test, title=title, severity=severity, reporter=cls.user)
            for title, severity in (("High one", "High"), ("High two", "High"), ("Low one", "Low"))
        ]

    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        self.findings_url = reverse("finding-list")

    def get(self, url, params):
        return self.client.get(url, params, format="json")

    def test_unknown_key_is_rejected_and_named(self):
        response = self.get(self.findings_url, {"not_a_filter": "x"})
        self.assertEqual(400, response.status_code, response.content[:500])
        self.assertIn("not_a_filter", response.json())

    def test_misspelled_filter_is_rejected(self):
        response = self.get(self.findings_url, {"severty": "Critical", "severity": "High"})
        self.assertEqual(400, response.status_code, response.content[:500])
        body = response.json()
        self.assertIn("severty", body)
        self.assertNotIn("severity", body)

    def test_every_unknown_key_is_named(self):
        response = self.get(self.findings_url, {"zz": "1", "aa": "2"})
        self.assertEqual(400, response.status_code)
        body = response.json()
        self.assertIn("zz", body)
        self.assertIn("aa", body)

    def test_reserved_params_are_accepted(self):
        params = {
            "limit": "2",
            "offset": "1",
            "o": "-id",
            "prefetch": "test",
            "related_fields": "true",
            "response_fields": "id,title",
            "format": "json",
        }
        self.assertTrue(set(params) <= RESERVED_QUERY_PARAMS)
        response = self.get(self.findings_url, params)
        self.assertEqual(200, response.status_code, response.content[:500])

    def test_declared_filters_and_their_variants_are_accepted(self):
        params = {
            "severity": "High",
            "test__engagement__product": str(Product.objects.get(name="Strict Filters Product").id),
            "tags__and": "x",
            "not_test__tags": "y",
            "epss_score_min": "0.1",
            "epss_score_max": "0.9",
        }
        response = self.get(self.findings_url, params)
        self.assertEqual(200, response.status_code, response.content[:500])

    def test_declared_filter_still_filters(self):
        response = self.get(self.findings_url, {"severity": "High", "limit": "100"})
        self.assertEqual(200, response.status_code)
        self.assertEqual(2, response.json()["count"])

    def test_list_without_a_filterset_rejects_any_filter(self):
        # ProductPlatformViewSet has the filter backend but no filterset: no filter is declared.
        response = self.get(reverse("product_platform-list"), {"name": "zz"})
        self.assertEqual(400, response.status_code, response.content[:500])
        self.assertIn("name", response.json())

    def test_detail_route_is_not_checked(self):
        response = self.get(reverse("finding-detail", args=(self.findings[0].id,)), {"not_a_filter": "x"})
        self.assertEqual(200, response.status_code, response.content[:500])

    def test_a_registered_reserved_param_is_accepted(self):
        self.addCleanup(strict_filters._registered_query_params.discard, "plugin_param")
        register_reserved_query_params("plugin_param")
        self.assertIn("plugin_param", reserved_query_params())
        response = self.get(self.findings_url, {"plugin_param": "1"})
        self.assertEqual(200, response.status_code, response.content[:500])

    def test_a_view_extra_query_param_is_accepted(self):
        response = self.get(reverse("finding-list"), {"zz": "1"})
        self.assertEqual(400, response.status_code)
        view = type("View", (), {"extra_query_params": ("zz",), "filter_backends": ()})()
        self.assertIn("zz", strict_filters.view_query_params(view))

    @override_settings(API_UNKNOWN_QUERY_PARAMS="warn")
    def test_warn_mode_serves_the_request_and_names_the_keys(self):
        with self.assertLogs("dojo.api_v2.strict_filters", level=logging.WARNING) as logs:
            response = self.get(self.findings_url, {"zz": "1", "aa": "2", "severity": "High"})
        self.assertEqual(200, response.status_code, response.content[:500])
        self.assertEqual("aa,zz", response[UNKNOWN_QUERY_PARAMS_HEADER])
        self.assertIn("aa, zz", logs.output[0])
        self.assertEqual(2, response.json()["count"])

    @override_settings(API_UNKNOWN_QUERY_PARAMS="off")
    def test_off_mode_ignores_unknown_keys(self):
        response = self.get(self.findings_url, {"not_a_filter": "x"})
        self.assertEqual(200, response.status_code)
        self.assertNotIn(UNKNOWN_QUERY_PARAMS_HEADER, response)
        self.assertEqual(3, response.json()["count"])

    def test_known_keys_send_no_warning_header(self):
        response = self.get(self.findings_url, {"severity": "High"})
        self.assertNotIn(UNKNOWN_QUERY_PARAMS_HEADER, response)


class StrictFilterPluginViewTest(DojoTestCase):

    """A plugin's view (any class outside the ``dojo`` package) is left to the plugin."""

    def test_a_view_defined_outside_open_source_is_not_checked(self):
        from rest_framework.request import Request  # noqa: PLC0415
        from rest_framework.test import APIRequestFactory  # noqa: PLC0415

        from dojo.finding.api.views import FindingViewSet  # noqa: PLC0415

        plugin_view_class = type("PluginFindingViewSet", (FindingViewSet,), {"__module__": "plugin.views"})
        view = plugin_view_class()
        view.kwargs = {}
        view.request = Request(APIRequestFactory().get("/", {"not_a_filter": "x"}))
        backend = strict_filters.StrictDjangoFilterBackend()
        queryset = Finding.objects.none()
        self.assertEqual(list(backend.filter_queryset(view.request, queryset, view)), [])

    def test_a_view_defined_by_open_source_is_checked(self):
        from rest_framework.exceptions import ValidationError  # noqa: PLC0415
        from rest_framework.request import Request  # noqa: PLC0415
        from rest_framework.test import APIRequestFactory  # noqa: PLC0415

        from dojo.finding.api.views import FindingViewSet  # noqa: PLC0415

        view = FindingViewSet()
        view.kwargs = {}
        view.request = Request(APIRequestFactory().get("/", {"not_a_filter": "x"}))
        with self.assertRaises(ValidationError):
            strict_filters.StrictDjangoFilterBackend().filter_queryset(view.request, Finding.objects.none(), view)


class _RangeFilterSet(django_filters.FilterSet):
    created = django_filters.DateFromToRangeFilter()
    pair = django_filters.Filter(widget=forms.MultiWidget(widgets=[forms.TextInput, forms.TextInput]))

    class Meta:
        model = Product_Type
        fields = {"name": ["exact", "icontains", "in"]}


class StrictFilterHelpersTest(DojoTestCase):

    def test_filterset_keys_include_lookups_and_widget_suffixes(self):
        names = filterset_query_params(_RangeFilterSet(data={}, queryset=Product_Type.objects.none()))
        self.assertLessEqual(
            {"name", "name__icontains", "name__in", "created_after", "created_before", "pair_0", "pair_1"},
            names,
        )
        self.assertNotIn("nme", names)

    def test_mode_defaults_to_enforce(self):
        self.assertEqual("enforce", unknown_query_params_mode())

    @override_settings(API_UNKNOWN_QUERY_PARAMS="loud")
    def test_unrecognised_mode_falls_back_to_enforce(self):
        self.assertEqual("enforce", unknown_query_params_mode())
