try:
    from dojo.authorization.query_filters import get_auth_filter
except ImportError:
    def get_auth_filter(key): return None

from dojo.models import Test, Test_Import
from dojo.request_cache import cache_for_request


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_tests(permission, product=None):
    impl = get_auth_filter("test.get_authorized_tests")
    if impl:
        return impl(permission, product=product)
    return Test.objects.all().order_by("id")


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request
def get_authorized_test_imports(permission):
    impl = get_auth_filter("test.get_authorized_test_imports")
    if impl:
        return impl(permission)
    return Test_Import.objects.all().order_by("id")
