try:
    from dojo.authorization.query_filters import get_auth_filter
except ImportError:
    def get_auth_filter(key): return None

from dojo.models import Cred_Mapping
from dojo.request_cache import cache_for_request


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_cred_mappings(permission):
    impl = get_auth_filter("cred.get_authorized_cred_mappings")
    if impl:
        return impl(permission)
    return Cred_Mapping.objects.all().order_by("id")


def get_authorized_cred_mappings_for_queryset(permission, queryset):
    impl = get_auth_filter("cred.get_authorized_cred_mappings_for_queryset")
    if impl:
        return impl(permission, queryset)
    return queryset
