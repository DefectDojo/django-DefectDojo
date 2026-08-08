from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import mixins, viewsets
from rest_framework.permissions import DjangoModelPermissions

from dojo.authorization import api_permissions as permissions
from dojo.notes.api.serializer import NoteSerializer
from dojo.notes.models import Notes


# Authorization: superuser
class NotesViewSet(
    mixins.UpdateModelMixin,
    viewsets.ReadOnlyModelViewSet,
):
    serializer_class = NoteSerializer
    queryset = Notes.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = [
        "id",
        "entry",
        "author",
        "private",
        "date",
        "edited",
        "edit_time",
        "editor",
    ]
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)

    def get_queryset(self):
        return Notes.objects.all().order_by("id")
