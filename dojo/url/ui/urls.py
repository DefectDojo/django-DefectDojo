# urls.py
from django.urls import re_path

from dojo.url.ui.views import (
    add_endpoint_to_finding,
    add_endpoint_to_product,
    all_endpoint_hosts,
    all_endpoints,
    delete_endpoint,
    edit_endpoint,
    endpoint_bulk_update_all,
    endpoint_host_report,
    endpoint_report,
    finding_location_bulk_update,
    import_endpoint_meta,
    manage_meta_data,
    migrate_endpoints_view,
    view_endpoint,
    view_endpoint_host,
    vulnerable_endpoint_hosts,
    vulnerable_endpoints,
)

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
    re_path(r"^endpoint/(?P<product_id>\d+)/import_endpoint_meta$", import_endpoint_meta, name="import_endpoint_meta"),
    re_path(r"^endpoint/bulk$", endpoint_bulk_update_all, name="endpoints_bulk_all"),
    re_path(
        r"^product/(?P<product_id>\d+)/endpoint/bulk_product$",
        endpoint_bulk_update_all,
        name="endpoints_bulk_update_all_product",
    ),
    re_path(r"^endpoint/(?P<finding_id>\d+)/bulk_status$", finding_location_bulk_update, name="endpoints_status_bulk"),
    re_path(r"^endpoint/migrate$", migrate_endpoints_view, name="endpoint_migrate"),
    re_path(r"^endpoint/(?P<location_id>\d+)/report$", endpoint_report,
        name="endpoint_report"),
    re_path(r"^endpoint/host/(?P<location_id>\d+)/report$", endpoint_host_report,
        name="endpoint_host_report"),
]
