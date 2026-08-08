import logging

from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema_view
from rest_framework.permissions import IsAuthenticated

from dojo.api_v2.views import PrefetchDojoModelViewSet, schema_with_prefetch
from dojo.authorization import api_permissions as permissions
from dojo.tool_product.api.serializer import ToolProductSettingsSerializer
from dojo.tool_product.models import Tool_Product_Settings
from dojo.tool_product.queries import get_authorized_tool_product_settings

logger = logging.getLogger(__name__)


# Authorization: object-based
@extend_schema_view(**schema_with_prefetch())
class ToolProductSettingsViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = ToolProductSettingsSerializer
    queryset = Tool_Product_Settings.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "name",
        "product",
        "tool_configuration",
        "tool_project_id",
        "url",
    ]
    permission_classes = (
        IsAuthenticated,
        permissions.UserHasToolProductSettingsPermission,
    )

    def get_queryset(self):
        return get_authorized_tool_product_settings("view")
