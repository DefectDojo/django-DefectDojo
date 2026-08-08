from rest_framework import mixins, viewsets
from rest_framework.permissions import DjangoModelPermissions

from dojo.authorization import api_permissions as permissions
from dojo.system_settings.api.serializer import SystemSettingsSerializer
from dojo.system_settings.models import System_Settings


# Authorization: superuser
class SystemSettingsViewSet(
    mixins.ListModelMixin, mixins.UpdateModelMixin, viewsets.GenericViewSet,
):

    """Basic control over System Settings. Use 'id' 1 for PUT, PATCH operations"""

    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)
    serializer_class = SystemSettingsSerializer
    queryset = System_Settings.objects.none()

    def get_queryset(self):
        return System_Settings.objects.all().order_by("id")
