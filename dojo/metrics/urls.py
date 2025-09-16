from django.conf import settings
from django.urls import re_path

from dojo.metrics import views
from dojo.utils import redirect_view

# TODO: remove the else: branch once v3 migration is complete
if settings.ENABLE_V3_ORGANIZATION_ASSET_RELABEL:
    urlpatterns = [
        #  metrics
        re_path(
            r"^metrics$",
            views.metrics,
            {"mtype": "All"},
                name="metrics",
        ),
        re_path(
            r"^critical_asset_metrics$",
            views.critical_product_metrics,
            {"mtype": "All"},
            name="critical_product_metrics",
        ),
        re_path(
            r"^metrics/all$",
            views.metrics,
            {"mtype": "All"},
            name="metrics_all",
        ),
        re_path(
            r"^metrics/organization$",
            views.metrics,
            {"mtype": "All"},
            name="metrics_product_type",
        ),
        re_path(
            r"^metrics/simple$",
            views.simple_metrics,
            name="simple_metrics",
        ),
        re_path(
            r"^metrics/organization/(?P<mtype>\d+)$",
            views.metrics,
            name="product_type_metrics",
        ),
        re_path(
            r"^metrics/organization/counts$",
            views.product_type_counts,
            name="product_type_counts",
        ),
        re_path(
            r"^metrics/asset/tag/counts$",
            views.product_tag_counts,
            name="product_tag_counts",
        ),
        re_path(
            r"^metrics/engineer$",
            views.engineer_metrics,
            name="engineer_metrics",
        ),
        re_path(
            r"^metrics/engineer/(?P<eid>\d+)$",
            views.view_engineer,
            name="view_engineer",
        ),
        # TODO: Backwards compatibility; remove after v3 migration is complete
        re_path(r"^critical_product_metrics$", redirect_view("critical_product_metrics")),
        re_path(r"^metrics/product/type$", redirect_view("metrics_product_type")),
        re_path(r"^metrics/product/type/(?P<mtype>\d+)$", redirect_view("product_type_metrics")),
        re_path(r"^metrics/product/type/counts$", redirect_view("product_type_counts")),
        re_path(r"^metrics/product/tag/counts$", redirect_view("product_tag_counts")),
    ]
else:
    urlpatterns = [
        #  metrics
        re_path(r"^metrics$", views.metrics, {"mtype": "All"},
            name="metrics"),
        re_path(r"^critical_product_metrics$", views.critical_product_metrics, {"mtype": "All"},
            name="critical_product_metrics"),
        re_path(r"^metrics/all$", views.metrics, {"mtype": "All"},
            name="metrics_all"),
        re_path(r"^metrics/product/type$", views.metrics, {"mtype": "All"},
            name="metrics_product_type"),
        re_path(r"^metrics/simple$", views.simple_metrics,
            name="simple_metrics"),
        re_path(r"^metrics/product/type/(?P<mtype>\d+)$",
            views.metrics, name="product_type_metrics"),
        re_path(r"^metrics/product/type/counts$",
            views.product_type_counts, name="product_type_counts"),
        re_path(r"^metrics/product/tag/counts$",
            views.product_tag_counts, name="product_tag_counts"),
        re_path(r"^metrics/engineer$", views.engineer_metrics,
            name="engineer_metrics"),
        re_path(r"^metrics/engineer/(?P<eid>\d+)$", views.view_engineer,
            name="view_engineer"),
        # Forward compatibility
        re_path(r"^critical_asset_metrics$", redirect_view("critical_product_metrics")),
        re_path(r"^metrics/organization$", redirect_view("metrics_product_type")),
        re_path(r"^metrics/organization/(?P<mtype>\d+)$", redirect_view("product_type_metrics")),
        re_path(r"^metrics/organization/counts$", redirect_view("product_type_counts")),
        re_path(r"^metrics/asset/tag/counts$", redirect_view("product_tag_counts")),
    ]
