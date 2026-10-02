from django_filters.rest_framework import DjangoFilterBackend

from dojo.announcement.api.serializer import AnnouncementSerializer
from dojo.announcement.models import Announcement
from dojo.api_v2.views import DojoModelViewSet
from dojo.authorization import api_permissions as permissions


# Authorization: configuration
class AnnouncementViewSet(
    DojoModelViewSet,
):
    serializer_class = AnnouncementSerializer
    queryset = Announcement.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = "__all__"
    permission_classes = (permissions.UserHasConfigurationPermissionStaff,)

    def get_queryset(self):
        return Announcement.objects.all().order_by("id")
