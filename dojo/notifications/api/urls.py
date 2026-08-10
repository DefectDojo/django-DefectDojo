from dojo.notifications.api import path
from dojo.notifications.api.views import (
    NotificationsViewSet,
    NotificationWebhooksViewSet,
)


def add_notifications_urls(router):
    router.register(rf"{path}", NotificationsViewSet, basename=path)
    router.register(r"notification_webhooks", NotificationWebhooksViewSet)
    return router
