# Regression: a non-numeric id in a UI query value made the page return 500.
from django.core.cache import cache
from django.urls import reverse

from dojo.location.models import Location
from dojo.models import Finding, Finding_Group, Product, Test
from dojo.utils import parse_ids
from unittests.dojo_test_case import DojoTestCase, skip_unless_v3, versioned_fixtures


class ParseIdsTest(DojoTestCase):

    def test_parse_ids_keeps_only_decimal_ids(self):
        self.assertEqual(parse_ids(["2", "abc", "-1", "²", "1.5", "", " 3", "1" * 20, "1" * 19]), [2, int("1" * 19)])


@versioned_fixtures
class NonNumericIdFilterTest(DojoTestCase):

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        cache.clear()
        self.client.force_login(self.get_test_admin())

    def get(self, url, query):
        return self.client.get(url + "?" + query)

    def test_endpoint_lists_non_numeric_product_return_200(self):
        for url_name in ("endpoint", "endpoint_host", "vulnerable_endpoints", "vulnerable_endpoint_hosts"):
            with self.subTest(url_name):
                response = self.get(reverse(url_name), "product=abc")
                self.assertEqual(response.status_code, 200)
                self.assertIsNone(response.context["product_tab"])

    def test_endpoint_list_single_product_shows_product_tab(self):
        response = self.get(reverse("endpoint"), f"product={Product.objects.first().id}")
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(response.context["product_tab"])

    @skip_unless_v3
    def test_view_endpoint_non_numeric_product_returns_200(self):
        location = Location.objects.first()
        response = self.get(reverse("view_endpoint", args=[location.id]), "product=abc")
        self.assertEqual(response.status_code, 200)

    def test_metrics_non_numeric_product_type_returns_200(self):
        response = self.get(reverse("metrics"), "test__engagement__product__prod_type=abc")
        self.assertEqual(response.status_code, 200)

    def test_finding_group_lists_non_numeric_filters_return_200(self):
        for url_name in ("all_finding_groups", "open_finding_groups", "closed_finding_groups"):
            with self.subTest(url_name):
                response = self.get(reverse(url_name), "product=abc&engagement=abc")
                self.assertEqual(response.status_code, 200)

    def test_finding_group_list_drops_non_numeric_ids(self):
        test = Test.objects.get(pk=3)
        group = Finding_Group.objects.create(name="Group A", test=test, creator=self.get_test_admin())
        group.findings.add(Finding.objects.get(pk=2))
        product_id = test.engagement.product_id
        for query, expected in (
            ("product=abc", []),
            ("engagement=abc", []),
            (f"product={product_id}&product=abc", [group.id]),
            (f"engagement={test.engagement_id}&engagement=abc", [group.id]),
        ):
            with self.subTest(query):
                response = self.get(reverse("all_finding_groups"), query)
                self.assertEqual(response.status_code, 200)
                self.assertEqual([fg.id for fg in response.context["finding_groups"]], expected)
