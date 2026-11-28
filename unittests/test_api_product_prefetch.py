from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils.timezone import now
from rest_framework.test import APITestCase

from dojo.models import (
    Dojo_User,
    DojoMeta,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Regulation,
    Test,
    Test_Type,
)


class TestProductListNPlusOne(APITestCase):

    """
    Regression: the /api/v2/products/ and /api/v3/assets/ list endpoints must
    load all serialized relations in bulk so that the query count does not grow
    with the number of products in the response.

    Before the fix, each product triggered separate queries for tags,
    product_meta, authorized_users, regulations, and the active-finding count
    — a classic N+1.  The optimized get_queryset() uses select_related for
    SlugRelatedField FKs, prefetch_related for M2M/reverse-FK relations, and a
    correlated subquery annotation for the finding count.

    Each test asserts that the query count with 1 product is identical to the
    query count with 5 products, proving zero per-product query growth.
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User.objects.create(
            username="prodprefetch_user", is_staff=True, is_superuser=True,
        )
        cls.prod_type = Product_Type.objects.create(name="ProdPrefetch PT")
        cls.test_type = Test_Type.objects.create(name="ProdPrefetch TT")
        cls.regulation = Regulation.objects.create(
            name="ProdPrefetch Reg", acronym="PPR", category="privacy",
            jurisdiction="international",
        )

    def setUp(self):
        self.client.force_authenticate(user=self.user)
        self.client.force_login(self.user)

    def _create_product(self, suffix, *, active=True):
        """Create a product with every relation the serializer renders."""
        product = Product.objects.create(
            name=f"ProdPrefetch Product {suffix}",
            prod_type=self.prod_type,
            description="N+1 test product",
        )
        product.tags.add("prefetch-tag-a", "prefetch-tag-b")
        product.authorized_users.add(self.user)
        product.regulations.add(self.regulation)
        DojoMeta.objects.create(product=product, name="key", value="val")

        engagement = Engagement.objects.create(
            name=f"ProdPrefetch Eng {suffix}",
            product=product,
            target_start=now(),
            target_end=now(),
        )
        test = Test.objects.create(
            title=f"ProdPrefetch Test {suffix}",
            engagement=engagement,
            test_type=self.test_type,
            target_start=now(),
            target_end=now(),
        )
        Finding.objects.create(
            title=f"ProdPrefetch Finding {suffix}",
            test=test,
            reporter=self.user,
            severity="High",
            active=active,
        )
        return product

    def _query_count(self, url):
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.content[:2000])
        return len(ctx.captured_queries)

    def _assert_constant_query_count(self, url, expected_growth=0, *, active=True):
        self._create_product("baseline", active=active)
        # Warm-up request: fills ContentType cache and other one-time lookups.
        self._query_count(url)
        with_one = self._query_count(url)

        extra_products = 4
        for i in range(extra_products):
            self._create_product(f"extra-{i}", active=active)
        with_five = self._query_count(url)

        per_product_growth = with_five - with_one
        # Include the active finding IDs in the constant-query guarantee.
        self.assertEqual(
            per_product_growth,
            expected_growth,
            f"{url}: expected +{expected_growth} queries for {extra_products} "
            f"extra products, got +{per_product_growth}",
        )

    def test_product_list_query_count_constant(self):
        self._assert_constant_query_count("/api/v2/products/")

    def test_product_list_query_count_constant_for_member(self):
        member = Dojo_User.objects.create(username="prodprefetch_member")
        self.client.force_authenticate(user=member)
        self.client.force_login(member)
        self.prod_type.authorized_users.add(member)
        self._assert_constant_query_count("/api/v2/products/")

    def test_product_list_query_count_constant_without_active_findings(self):
        self._assert_constant_query_count("/api/v2/products/", active=False)

    def test_product_list_preserves_active_finding_ids_and_order(self):
        product = self._create_product("findings")
        test = Test.objects.get(engagement__product=product)
        for title, severity, numerical_severity, active in (
            ("First", "Critical", "S0", True),
            ("Last", "Low", "S3", True),
            ("Inactive", "High", "S1", False),
        ):
            Finding.objects.create(
                test=test, reporter=self.user, title=title, severity=severity,
                numerical_severity=numerical_severity, active=active,
            )
        other = self._create_product("other")
        other_test = Test.objects.get(engagement__product=other)
        Finding.objects.filter(test=other_test).update(active=False)
        extra_engagement = Engagement.objects.create(
            product=product, name="Another engagement", target_start=now(), target_end=now(),
        )
        extra_test = Test.objects.create(
            engagement=extra_engagement, test_type=self.test_type, target_start=now(), target_end=now(),
        )
        Finding.objects.create(
            test=extra_test, reporter=self.user, title="Active false positive", severity="Medium",
            numerical_severity="S2", active=True, false_p=True,
        )

        response = self.client.get("/api/v2/products/", {"limit": 100})
        self.assertEqual(200, response.status_code)
        rows = {row["id"]: row for row in response.data["results"]}
        expected = product.open_findings_list()
        self.assertEqual(4, len(expected))
        self.assertEqual(expected, rows[product.id]["findings_list"])
        self.assertEqual(4, rows[product.id]["findings_count"])
        self.assertEqual([], rows[other.id]["findings_list"])
        self.assertEqual(0, rows[other.id]["findings_count"])

    def test_product_list_respects_pagination_and_filtering(self):
        products = [self._create_product(f"page-{idx}") for idx in range(3)]
        for offset, product in enumerate(products):
            response = self.client.get("/api/v2/products/", {"limit": 1, "offset": offset})
            self.assertEqual(200, response.status_code)
            self.assertEqual(3, response.data["count"])
            self.assertEqual([product.id], [row["id"] for row in response.data["results"]])
            self.assertEqual(product.open_findings_list(), response.data["results"][0]["findings_list"])

        response = self.client.get("/api/v2/products/", {"id": products[1].id})
        self.assertEqual(200, response.status_code)
        self.assertEqual([products[1].id], [row["id"] for row in response.data["results"]])
        self.assertEqual(products[1].open_findings_list(), response.data["results"][0]["findings_list"])

    def test_product_list_does_not_include_unauthorized_products(self):
        allowed = self._create_product("allowed")
        self._create_product("forbidden")
        member = Dojo_User.objects.create(username="prodprefetch_restricted")
        allowed.authorized_users.add(member)
        self.client.force_authenticate(user=member)
        self.client.force_login(member)

        response = self.client.get("/api/v2/products/")
        self.assertEqual(200, response.status_code)
        self.assertEqual([allowed.id], [row["id"] for row in response.data["results"]])
        self.assertEqual(allowed.open_findings_list(), response.data["results"][0]["findings_list"])

    def test_product_list_empty_page(self):
        self._create_product("empty-page")
        response = self.client.get("/api/v2/products/", {"offset": 10})
        self.assertEqual(200, response.status_code)
        self.assertEqual([], response.data["results"])

    def test_product_retrieve_preserves_active_finding_ids(self):
        product = self._create_product("retrieve")
        response = self.client.get(f"/api/v2/products/{product.id}/")
        self.assertEqual(200, response.status_code)
        self.assertEqual(product.open_findings_list(), response.data["findings_list"])

    @classmethod
    def _v3_enabled(cls):
        from django.conf import settings  # noqa: PLC0415
        return getattr(settings, "V3_FEATURE_LOCATIONS", False)

    def test_asset_list_query_count_constant(self):
        if not self._v3_enabled():
            self.skipTest("V3_FEATURE_LOCATIONS is disabled")
        self._assert_constant_query_count("/api/v3/assets", expected_growth=0)
