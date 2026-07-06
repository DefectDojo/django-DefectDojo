from dojo.endpoint.api.views import EndpointMetaImporterView, EndpointStatusViewSet, EndPointViewSet


def add_endpoint_urls(router):
    """
    Register endpoint/endpoint_status routes (non-V3 block only).

    endpoint_meta_import is always registered via register_endpoint_meta_import.
    endpoints and endpoint_status are registered only when V3_FEATURE_LOCATIONS is OFF;
    the V3 compat viewsets are registered by dojo/location/api/urls.py instead.
    """
    router.register(r"endpoints", EndPointViewSet, basename="endpoint")
    router.register(r"endpoint_status", EndpointStatusViewSet, basename="endpoint_status")
    return router


def register_endpoint_meta_import(router):
    """Register the unconditional endpoint_meta_import route."""
    router.register(r"endpoint_meta_import", EndpointMetaImporterView, basename="endpointmetaimport")
    return router
