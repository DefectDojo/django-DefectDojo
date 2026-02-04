from dojo.models import Product, Product_Type
from dojo.product_type.views import prefetch_for_product_type
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


@versioned_fixtures
class TestProductTypeCounts(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def test_prefetch_for_product_type_prod_count_matches_direct_count(self):
        product_type = Product_Type.objects.create(name="PT count test")
        Product.objects.create(name="PT product 1", description="test", prod_type=product_type)
        Product.objects.create(name="PT product 2", description="test", prod_type=product_type)

        annotated = prefetch_for_product_type(Product_Type.objects.filter(id=product_type.id))
        annotated_count = annotated.values_list("prod_count", flat=True).get()

        direct_count = Product.objects.filter(prod_type_id=product_type.id).count()
        self.assertEqual(annotated_count, direct_count)
