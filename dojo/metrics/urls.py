from django.urls import re_path

from dojo.metrics import views
from dojo.v3_migration import redirect_view

common_urlpatterns = [
    re_path(r"^metrics$", views.metrics, {"mtype": "All"},
            name="metrics"),
    re_path(r"^metrics/all$", views.metrics, {"mtype": "All"},
            name="metrics_all"),
    re_path(r"^metrics/simple$", views.simple_metrics,
            name="simple_metrics"),
    re_path(r"^metrics/engineer$", views.engineer_metrics,
            name="engineer_metrics"),
    re_path(r"^metrics/engineer/(?P<eid>\d+)$", views.view_engineer,
            name="view_engineer"),
]


v2_urlpatterns = [
    re_path(r"^critical_product_metrics$", views.critical_product_metrics, {"mtype": "All"},
            name="critical_product_metrics"),
    re_path(r"^metrics/product/type$", views.metrics, {"mtype": "All"},
            name="metrics_product_type"),
    re_path(r"^metrics/product/type/(?P<mtype>\d+)$",
            views.metrics, name="product_type_metrics"),
    re_path(r"^metrics/product/type/counts$",
            views.product_type_counts, name="product_type_counts"),
    re_path(r"^metrics/product/tag/counts$",
            views.product_tag_counts, name="product_tag_counts"),
]


v3_forward_urlpatterns = [
    re_path(r"^critical_asset_metrics$", redirect_view("critical_product_metrics")),
    re_path(r"^metrics/organization$", redirect_view("metrics_product_type")),
    re_path(r"^metrics/organization/(?P<mtype>\d+)$", redirect_view("product_type_metrics")),
    re_path(r"^metrics/organization/counts$", redirect_view("product_type_counts")),
]


urlpatterns = common_urlpatterns + v2_urlpatterns + v3_forward_urlpatterns
