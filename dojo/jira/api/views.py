from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema_view
from rest_framework.permissions import IsAuthenticated

from dojo.api_v2 import permissions
from dojo.api_v2.views import DojoModelViewSet, PrefetchDojoModelViewSet, schema_with_prefetch
from dojo.authorization.roles_permissions import Permissions
from dojo.jira.api.serializers import (
    JIRAInstanceSerializer,
    JIRAIssueSerializer,
    JIRAProjectSerializer,
)
from dojo.jira.queries import (
    get_authorized_jira_issues,
    get_authorized_jira_projects,
)
from dojo.models import (
    JIRA_Instance,
    JIRA_Issue,
    JIRA_Project,
)


class JiraInstanceViewSet(
    DojoModelViewSet,
):
    serializer_class = JIRAInstanceSerializer
    queryset = JIRA_Instance.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "url"]
    permission_classes = (permissions.UserHasConfigurationPermissionSuperuser,)

    def get_queryset(self):
        return JIRA_Instance.objects.all().order_by("id")


# Authorization: object-based
# @extend_schema_view(**schema_with_prefetch())
# Nested models with prefetch make the response schema too long for Swagger UI
class JiraIssuesViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = JIRAIssueSerializer
    queryset = JIRA_Issue.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "jira_id",
        "jira_key",
        "finding",
        "engagement",
        "finding_group",
    ]

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasJiraIssuePermission,
    )

    def get_queryset(self):
        return get_authorized_jira_issues(Permissions.Product_View)


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class JiraProjectViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = JIRAProjectSerializer
    queryset = JIRA_Project.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "jira_instance",
        "product",
        "engagement",
        "enabled",
        "component",
        "project_key",
        "push_all_issues",
        "enable_engagement_epic_mapping",
        "push_notes",
    ]

    permission_classes = (
        IsAuthenticated,
        permissions.UserHasJiraProductPermission,
    )

    def get_queryset(self):
        return get_authorized_jira_projects(Permissions.Product_View)
