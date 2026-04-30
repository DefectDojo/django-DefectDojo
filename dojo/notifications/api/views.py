from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema_view
from rest_framework.permissions import DjangoModelPermissions

from dojo.authorization import api_permissions as permissions
from dojo.api_v2.views import PrefetchDojoModelViewSet, schema_with_prefetch
from dojo.notifications.api.serializer import (
    NotificationsSerializer,
    NotificationWebhooksSerializer,
)
from dojo.notifications.models import Notification_Webhooks, Notifications


# Authorization: superuser
@extend_schema_view(**schema_with_prefetch())
class NotificationsViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = NotificationsSerializer
    queryset = Notifications.objects.none()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "user", "product", "template"]
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)

    def get_queryset(self):
        return Notifications.objects.all().order_by("id")


class NotificationWebhooksViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = NotificationWebhooksSerializer
    queryset = Notification_Webhooks.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = "__all__"
    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)  # TODO: add permission also for other users
