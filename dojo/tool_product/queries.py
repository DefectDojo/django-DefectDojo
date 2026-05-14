try:
    from dojo.authorization.query_filters import get_auth_filter
except ImportError:
    def get_auth_filter(key): return None

from dojo.models import Tool_Product_Settings
from dojo.request_cache import cache_for_request


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_tool_product_settings(permission):
    impl = get_auth_filter("tool_product.get_authorized_tool_product_settings")
    if impl:
        return impl(permission)
    return Tool_Product_Settings.objects.all().order_by("id")
