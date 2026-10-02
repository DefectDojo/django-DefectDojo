import logging
from datetime import datetime

from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema_view

from dojo.api_v2.views import DeprecationNoticeMixin, PrefetchDojoModelViewSet, schema_with_prefetch
from dojo.authorization import api_permissions as permissions
from dojo.tool_config.api.serializer import ToolConfigurationSerializer
from dojo.tool_config.models import Tool_Configuration

logger = logging.getLogger(__name__)


# Authorization: configurations
# Deprecated in 3.2.0, removal planned for 3.5.0 (serves the API-based pull parsers).
@extend_schema_view(**schema_with_prefetch())
class ToolConfigurationsViewSet(
    DeprecationNoticeMixin,
    PrefetchDojoModelViewSet,
):
    deprecated = True
    end_of_life_date = datetime(2026, 11, 1)
    serializer_class = ToolConfigurationSerializer
    queryset = Tool_Configuration.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "name",
        "tool_type",
        "url",
        "authentication_type",
    ]
    permission_classes = (permissions.UserHasConfigurationPermissionSuperuser,)

    def get_queryset(self):
        return Tool_Configuration.objects.all().order_by("id")
