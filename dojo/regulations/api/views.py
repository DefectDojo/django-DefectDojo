from rest_framework.permissions import IsAuthenticated

from dojo.api_v2.strict_filters import StrictDjangoFilterBackend
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
    filter_backends = (StrictDjangoFilterBackend,)
    filterset_fields = ["id", "name", "description"]
    permission_classes = (IsAuthenticated, permissions.UserHasRegulationPermission)

    def get_queryset(self):
        return Regulation.objects.all().order_by("id")
