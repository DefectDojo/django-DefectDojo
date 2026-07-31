from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.http import QueryDict
from django.test import RequestFactory, SimpleTestCase, override_settings

from dojo.product.ui import views


class ProductListPaginationAnnotationTests(SimpleTestCase):
    def test_product_list_ordering_detects_findings_count(self):
        factory = RequestFactory()

        self.assertFalse(views.product_list_orders_by_findings_count(factory.get("/products")))
        self.assertFalse(views.product_list_orders_by_findings_count(factory.get("/products?o=name")))
        self.assertTrue(views.product_list_orders_by_findings_count(factory.get("/products?o=-findings_count")))
        self.assertTrue(views.product_list_orders_by_findings_count(factory.get("/products?o=name,-findings_count")))

    @override_settings(V3_FEATURE_LOCATIONS=True)
    @patch("dojo.product.ui.views.render")
    @patch("dojo.product.ui.views.add_breadcrumb")
    @patch("dojo.product.ui.views.get_system_setting", return_value=False)
    @patch("dojo.product.ui.views.prefetch_for_product")
    @patch("dojo.product.ui.views.get_page_items")
    @patch("dojo.product.ui.views.ProductFilter")
    @patch("dojo.product.ui.views.annotate_product_findings_count")
    @patch("dojo.product.ui.views.get_authorized_products")
    def test_product_list_defers_count_annotations_until_after_pagination(
        self,
        get_authorized_products,
        annotate_product_findings_count,
        product_filter,
        get_page_items,
        prefetch_for_product,
        get_system_setting,
        add_breadcrumb,
        render,
    ):
        base_qs = MagicMock(name="base_qs")
        base_qs.values_list.return_value = ["Product A"]
        get_authorized_products.return_value = base_qs

        filtered_qs = MagicMock(name="filtered_qs")
        distinct_qs = MagicMock(name="distinct_qs")
        filtered_qs.distinct.return_value = distinct_qs
        product_filter.return_value = SimpleNamespace(qs=filtered_qs)

        page = SimpleNamespace(object_list=distinct_qs)
        get_page_items.return_value = page
        prefetch_for_product.return_value = ["prefetched-page"]
        render.return_value = SimpleNamespace(status_code=200)

        request = RequestFactory().get("/products")
        request.user = MagicMock()

        views.product(request)

        get_system_setting.assert_called()
        add_breadcrumb.assert_called_once()
        annotate_product_findings_count.assert_not_called()
        filtered_qs.distinct.assert_called_once_with()
        get_page_items.assert_called_once_with(request, distinct_qs, 25)
        prefetch_for_product.assert_called_once_with(distinct_qs)

    @patch("dojo.product.ui.views.render")
    @patch("dojo.product.ui.views.add_breadcrumb")
    @patch("dojo.product.ui.views.get_system_setting", return_value=False)
    @patch("dojo.product.ui.views.prefetch_for_product")
    @patch("dojo.product.ui.views.get_page_items")
    @patch("dojo.product.ui.views.ProductFilter")
    @patch("dojo.product.ui.views.annotate_product_findings_count")
    @patch("dojo.product.ui.views.get_authorized_products")
    def test_product_list_keeps_findings_count_annotation_when_sorting_by_it(
        self,
        get_authorized_products,
        annotate_product_findings_count,
        product_filter,
        get_page_items,
        prefetch_for_product,
        get_system_setting,
        add_breadcrumb,
        render,
    ):
        base_qs = MagicMock(name="base_qs")
        base_qs.values_list.return_value = ["Product A"]
        annotated_qs = MagicMock(name="annotated_qs")
        annotate_product_findings_count.return_value = annotated_qs
        get_authorized_products.return_value = base_qs

        filtered_qs = MagicMock(name="filtered_qs")
        distinct_qs = MagicMock(name="distinct_qs")
        filtered_qs.distinct.return_value = distinct_qs
        product_filter.return_value = SimpleNamespace(qs=filtered_qs)

        page = SimpleNamespace(object_list=distinct_qs)
        get_page_items.return_value = page
        prefetch_for_product.return_value = ["prefetched-page"]
        render.return_value = SimpleNamespace(status_code=200)

        query = QueryDict("o=-findings_count")
        request = RequestFactory().get("/products")
        request.GET = query
        request.user = MagicMock()

        views.product(request)

        get_system_setting.assert_called()
        add_breadcrumb.assert_called_once()
        annotate_product_findings_count.assert_called_once_with(base_qs)
        product_filter.assert_called_once_with(request.GET, queryset=annotated_qs, user=request.user)
        filtered_qs.distinct.assert_called_once_with()
        get_page_items.assert_called_once_with(request, distinct_qs, 25)
