from dojo.api_v2.strict_filters import StrictDjangoFilterBackend
from dojo.api_v2.views import DojoModelViewSet
from dojo.authorization import api_permissions as permissions
from dojo.note_type.api.serializer import NoteTypeSerializer
from dojo.note_type.models import Note_Type


# Authorization: configuration
class NoteTypeViewSet(
    DojoModelViewSet,
):
    serializer_class = NoteTypeSerializer
    queryset = Note_Type.objects.none()
    filter_backends = (StrictDjangoFilterBackend,)
    filterset_fields = [
        "id",
        "name",
        "description",
        "is_single",
        "is_active",
        "is_mandatory",
    ]
    permission_classes = (permissions.UserHasConfigurationPermissionSuperuser,)

    def get_queryset(self):
        return Note_Type.objects.all().order_by("id")
