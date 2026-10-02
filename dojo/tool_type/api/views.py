import logging
from datetime import datetime

from django_filters.rest_framework import DjangoFilterBackend

from dojo.api_v2.views import DeprecationNoticeMixin, DojoModelViewSet
from dojo.authorization import api_permissions as permissions
from dojo.tool_type.api.serializer import ToolTypeSerializer
from dojo.tool_type.models import Tool_Type

logger = logging.getLogger(__name__)


# Authorization: configuration
# Deprecated in 3.2.0, removal planned for 3.5.0 (serves the API-based pull parsers).
class ToolTypesViewSet(
    DeprecationNoticeMixin,
    DojoModelViewSet,
):
    deprecated = True
    end_of_life_date = datetime(2026, 11, 1)
    serializer_class = ToolTypeSerializer
    queryset = Tool_Type.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "name", "description"]
    permission_classes = (permissions.UserHasConfigurationPermissionSuperuser,)

    def get_queryset(self):
        return Tool_Type.objects.all().order_by("id")
