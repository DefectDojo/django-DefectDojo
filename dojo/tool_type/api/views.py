import logging

from django_filters.rest_framework import DjangoFilterBackend

from dojo.api_v2.views import DojoModelViewSet
from dojo.authorization import api_permissions as permissions
from dojo.tool_type.api.serializer import ToolTypeSerializer
from dojo.tool_type.models import Tool_Type

logger = logging.getLogger(__name__)


# Authorization: configuration
class ToolTypesViewSet(
    DojoModelViewSet,
):
    serializer_class = ToolTypeSerializer
    queryset = Tool_Type.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "name", "description"]
    permission_classes = (permissions.UserHasConfigurationPermissionSuperuser,)

    def get_queryset(self):
        return Tool_Type.objects.all().order_by("id")
