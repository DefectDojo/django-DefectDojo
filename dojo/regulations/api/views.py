from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.permissions import IsAuthenticated

from dojo.api_v2.views import DojoModelViewSet
from dojo.authorization import api_permissions as permissions
from dojo.regulations.api.serializer import RegulationSerializer
from dojo.regulations.models import Regulation


# Authorization: authenticated, configuration
class RegulationsViewSet(
    DojoModelViewSet,
):
    serializer_class = RegulationSerializer
    queryset = Regulation.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "name", "description"]
    permission_classes = (IsAuthenticated, permissions.UserHasRegulationPermission)

    def get_queryset(self):
        return Regulation.objects.all().order_by("id")
