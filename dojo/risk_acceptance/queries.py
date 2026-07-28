try:
    from dojo.authorization.query_filters import get_auth_filter
except ImportError:
    def get_auth_filter(key): return None

from dojo.models import Risk_Acceptance
from dojo.request_cache import cache_for_request_or_task


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request_or_task
def get_authorized_risk_acceptances(permission):
    impl = get_auth_filter("risk_acceptance.get_authorized_risk_acceptances")
    if impl:
        return impl(permission)
    return Risk_Acceptance.objects.all().order_by("id")
