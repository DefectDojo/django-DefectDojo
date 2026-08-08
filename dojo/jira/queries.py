try:
    from dojo.authorization.query_filters import get_auth_filter
except ImportError:
    def get_auth_filter(key): return None

from dojo.models import JIRA_Issue, JIRA_Project
from dojo.request_cache import cache_for_request_or_task


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request_or_task
def get_authorized_jira_projects(permission, user=None):
    impl = get_auth_filter("jira_link.get_authorized_jira_projects")
    if impl:
        return impl(permission, user=user)
    return JIRA_Project.objects.all().order_by("id")


# Cached: all parameters are hashable, no dynamic queryset filtering
@cache_for_request_or_task
def get_authorized_jira_issues(permission):
    impl = get_auth_filter("jira_link.get_authorized_jira_issues")
    if impl:
        return impl(permission)
    return JIRA_Issue.objects.all().order_by("id")
