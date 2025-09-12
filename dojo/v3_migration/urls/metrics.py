from django.urls import re_path

from dojo.metrics import views
from dojo.metrics.urls import common_urlpatterns
from dojo.v3_migration import redirect_view

v3_urlpatterns = [
    re_path(r"^critical_asset_metrics$", views.critical_product_metrics, {"mtype": "All"},
            name="critical_product_metrics"),
    re_path(r"^metrics/organization$", views.metrics, {"mtype": "All"},
            name="metrics_product_type"),
    re_path(r"^metrics/organization/(?P<mtype>\d+)$",
            views.metrics, name="product_type_metrics"),
    re_path(r"^metrics/organization/counts$",
            views.product_type_counts, name="product_type_counts"),
    re_path(r"^metrics/asset/tag/counts$",
            views.product_tag_counts, name="product_tag_counts"),
]

v2_backward_urlpatterns = [
        re_path(r"^critical_product_metrics$", redirect_view("critical_product_metrics")),
        re_path(r"^metrics/product/type$", redirect_view("metrics_product_type")),
        re_path(r"^metrics/product/type/(?P<mtype>\d+)$", redirect_view("product_type_metrics")),
        re_path(r"^metrics/product/type/counts$", redirect_view("product_type_counts")),
]


urlpatterns = common_urlpatterns + v3_urlpatterns + v2_backward_urlpatterns
