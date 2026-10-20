from django.urls import re_path

from dojo.export.api.views import ExportManifestView, ProductExportView
from dojo.utils import get_system_setting


def add_export_urls(urls: list) -> list:
    prefix = get_system_setting("url_prefix")
    return [
        *urls,
        re_path(rf"^{prefix}api/v2/export/manifest/$", ExportManifestView.as_view(), name="export-manifest"),
        re_path(rf"^{prefix}api/v2/export/products/(?P<pk>\d+)/$", ProductExportView.as_view(), name="export-product"),
    ]
