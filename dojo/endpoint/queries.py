try:
    from dojo.authorization.query_filters import get_auth_filter
except ImportError:
    def get_auth_filter(key): return None

from dojo.models import (
    Endpoint,
    Endpoint_Status,
)
from dojo.request_cache import cache_for_request_or_task


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request_or_task
def get_authorized_endpoints(permission, user=None):
    impl = get_auth_filter("endpoint.get_authorized_endpoints")
    if impl:
        return impl(permission, user=user)
    return Endpoint.objects.all().order_by("id")


def get_import_form_endpoints(product, user):
    """Endpoints offered on the import and re-import forms: the product's own, else the ones the user can view."""
    endpoints = Endpoint.objects.filter(product=product)
    if endpoints.exists():
        return endpoints
    return get_authorized_endpoints("view", user=user)


def get_authorized_endpoints_for_queryset(permission, queryset, user=None):
    impl = get_auth_filter("endpoint.get_authorized_endpoints_for_queryset")
    if impl:
        return impl(permission, queryset, user=user)
    return queryset


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request_or_task
def get_authorized_endpoint_status(permission, user=None):
    impl = get_auth_filter("endpoint.get_authorized_endpoint_status")
    if impl:
        return impl(permission, user=user)
    return Endpoint_Status.objects.all().order_by("id")


def get_authorized_endpoint_status_for_queryset(permission, queryset, user=None):
    impl = get_auth_filter("endpoint.get_authorized_endpoint_status_for_queryset")
    if impl:
        return impl(permission, queryset, user=user)
    return queryset
