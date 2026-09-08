from django.http import QueryDict
from django.test import override_settings

from dojo.filters import filter_endpoints_host_base
from dojo.location.models import LocationProductReference
from dojo.location.status import ProductLocationStatus
from dojo.models import Product, Product_Type
from dojo.product.ui.filters import ProductFilter
from dojo.product.ui.views import annotate_product_location_counts
from dojo.url.models import URL
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


@versioned_fixtures
class ProductListPaginationAnnotationTests(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    @staticmethod
    def _make_product_with_locations():
        product_type = Product_Type.objects.create(name="Product list location counts")
        product = Product.objects.create(
            name="Product with duplicate location hosts",
            prod_type=product_type,
            description="Regression test product",
        )
        urls = [
            URL.create_location_from_value("https://duplicate.example/one"),
            URL.create_location_from_value("https://duplicate.example/two"),
            URL.create_location_from_value("https://other.example/"),
        ]
        for url in urls:
            LocationProductReference.objects.create(
                location=url.location,
                product=product,
                status=ProductLocationStatus.Active,
            )
        return product

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_location_counts_use_subqueries_without_product_group_by(self):
        product = self._make_product_with_locations()

        queryset = annotate_product_location_counts(Product.objects.filter(id=product.id))
        sql = str(queryset.query)
        annotated = queryset.get()

        self.assertEqual(annotated.location_count, 3)
        self.assertEqual(annotated.location_host_count, 2)
        self.assertNotIn('LEFT OUTER JOIN "dojo_locationproductreference"', sql)
        self.assertNotIn('GROUP BY "dojo_product"', sql)

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_product_endpoint_host_filter_deduplicates_products(self):
        product = self._make_product_with_locations()

        data = QueryDict(mutable=True)
        data["endpoints__host"] = "duplicate.example"
        prod_filter = ProductFilter(data, queryset=Product.objects.all(), user=self.get_test_admin())

        self.assertEqual(list(prod_filter.qs.filter(id=product.id).values_list("id", flat=True)), [product.id])

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_product_endpoint_id_filter_deduplicates_products(self):
        product = self._make_product_with_locations()
        location_id = product.locations.first().location_id

        data = QueryDict(mutable=True)
        data["endpoints"] = str(location_id)
        prod_filter = ProductFilter(data, queryset=Product.objects.all(), user=self.get_test_admin())

        self.assertEqual(list(prod_filter.qs.filter(id=product.id).values_list("id", flat=True)), [product.id])

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_product_location_status_filter_deduplicates_products(self):
        product = self._make_product_with_locations()

        data = QueryDict(mutable=True)
        data.setlist("location_status", [ProductLocationStatus.Active])
        prod_filter = ProductFilter(data, queryset=Product.objects.all(), user=self.get_test_admin())

        self.assertEqual(list(prod_filter.qs.filter(id=product.id).values_list("id", flat=True)), [product.id])

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_shared_endpoint_host_helper_does_not_deduplicate_findings_scope(self):
        product = self._make_product_with_locations()

        filtered = filter_endpoints_host_base(Product.objects.all(), "endpoints__host", "duplicate.example")

        self.assertEqual(list(filtered.filter(id=product.id).values_list("id", flat=True)), [product.id, product.id])
