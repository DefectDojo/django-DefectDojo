"""Schema regression test for the case-insensitive product-name index.

Regression: DJANGO-D2M — filtering findings by product name issues
``WHERE UPPER(dojo_product.name) = UPPER(%s)``. The plain unique btree on
dojo_product.name can't serve that predicate, so a functional Upper(name) index
is required to keep the lookup fast.
"""
from django.db import connection
from django.test import TestCase

INDEX_NAME = "dojo_product_upper_name_idx"


class ProductUpperNameIndexTest(TestCase):
    def test_upper_name_functional_index_exists(self):
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT indexdef FROM pg_indexes WHERE tablename = 'dojo_product' AND indexname = %s",
                [INDEX_NAME],
            )
            row = cursor.fetchone()
        self.assertIsNotNone(row, f"expected functional index {INDEX_NAME} on dojo_product")
        self.assertIn("upper", row[0].lower(), f"index {INDEX_NAME} is not on UPPER(name): {row[0]}")
