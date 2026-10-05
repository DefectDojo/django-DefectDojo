from dojo.export.api import path
from dojo.export.api.views import ExportViewSet


def add_export_urls(router):
    router.register(path, ExportViewSet, basename="export")
    return router
