# urls.py
from django.urls import re_path

from dojo.url.ui.views import (
    all_endpoints,
    all_endpoint_hosts,
    vulnerable_endpoints,
    vulnerable_endpoint_hosts,
    view_endpoint,
    view_endpoint_host,
    edit_endpoint,
    add_endpoint_to_product,
    add_endpoint_to_product,
    add_endpoint_to_finding,
    delete_endpoint,
    manage_meta_data,
)
from dojo.endpoint import views

urlpatterns = [
    re_path(r"^endpoint$", all_endpoints, name="endpoint"),
    re_path(r"^endpoint/host$", all_endpoint_hosts, name="endpoint_host"),
    re_path(r"^endpoint/vulnerable$", vulnerable_endpoints, name="vulnerable_endpoints"),
    re_path(r"^endpoint/host/vulnerable$", vulnerable_endpoint_hosts, name="vulnerable_endpoint_hosts"),
    re_path(r"^endpoint/(?P<location_id>\d+)$", view_endpoint, name="view_endpoint"),
    re_path(r"^endpoint/host/(?P<location_id>\d+)$", view_endpoint_host, name="view_endpoint_host"),
    re_path(r"^endpoint/(?P<location_id>\d+)/edit$", edit_endpoint, name="edit_endpoint"),
    re_path(r"^endpoints/product/(?P<product_id>\d+)/add$", add_endpoint_to_product, name="add_endpoint_to_product"),
    re_path(r"^endpoints/finding/(?P<finding_id>\d+)/add$", add_endpoint_to_finding, name="add_endpoint_to_finding"),
    # Add a duplicate route for adding legacy usage
    re_path(r"^endpoints/product/(?P<product_id>\d+)/add$", add_endpoint_to_product, name="add_endpoint"),
    re_path(r"^endpoint/(?P<location_id>\d+)/delete$", delete_endpoint, name="delete_endpoint"),
    re_path(r"^endpoint/(?P<location_id>\d+)/add_meta_data$", manage_meta_data, name="add_endpoint_meta_data"),
    re_path(r"^endpoint/(?P<location_id>\d+)/edit_meta_data$", manage_meta_data, name="edit_endpoint_meta_data"),


    re_path(r"^endpoint/bulk$", views.endpoint_bulk_update_all, name="endpoints_bulk_all"),
    re_path(
        r"^product/(?P<pid>\d+)/endpoint/bulk_product$",
        views.endpoint_bulk_update_all,
        name="endpoints_bulk_update_all_product",
    ),
    re_path(r"^endpoint/(?P<fid>\d+)/bulk_status$", views.endpoint_status_bulk_update, name="endpoints_status_bulk"),
    re_path(r"^endpoint/migrate$", views.migrate_endpoints_view, name="endpoint_migrate"),
    re_path(r"^endpoint/(?P<pid>\d+)/import_endpoint_meta$", views.import_endpoint_meta, name="import_endpoint_meta"),
]
