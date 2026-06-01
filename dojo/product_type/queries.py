try:
    from dojo.authorization.query_filters import get_auth_filter
except ImportError:
    def get_auth_filter(key): return None

from dojo.models import Product_Type
from dojo.request_cache import cache_for_request


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_product_types(permission):
    impl = get_auth_filter("product_type.get_authorized_product_types")
    if impl:
        return impl(permission)
    return Product_Type.objects.all().order_by("name")
