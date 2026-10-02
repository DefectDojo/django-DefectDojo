from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.permissions import IsAuthenticated

from dojo.api_v2.views import DojoModelViewSet
from dojo.authorization import api_permissions as permissions
from dojo.development_environment.api.serializer import DevelopmentEnvironmentSerializer
from dojo.development_environment.models import Development_Environment


# Authorization: authenticated, configuration
class DevelopmentEnvironmentViewSet(
    DojoModelViewSet,
):
    serializer_class = DevelopmentEnvironmentSerializer
    queryset = Development_Environment.objects.none()
    filter_backends = (DjangoFilterBackend,)
    permission_classes = (IsAuthenticated, permissions.UserHasDevelopmentEnvironmentPermission)

    def get_queryset(self):
        return Development_Environment.objects.all().order_by("id")
