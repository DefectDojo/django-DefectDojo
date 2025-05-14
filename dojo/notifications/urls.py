from django.urls import re_path

from . import views

urlpatterns = [
    re_path(r"^notifications$", views.PersonalNotificationsView.as_view(), name="notifications"),
    re_path(r"^notifications/system$", views.SystemNotificationsView.as_view(), name="system_notifications"),
    re_path(r"^notifications/personal$", views.PersonalNotificationsView.as_view(), name="personal_notifications"),
    re_path(r"^notifications/template$", views.TemplateNotificationsView.as_view(), name="template_notifications"),
    re_path(r"^notifications/webhooks$", views.ListNotificationWebhooksView.as_view(), name="notification_webhooks"),
    re_path(r"^notifications/webhooks/add$", views.AddNotificationWebhooksView.as_view(), name="add_notification_webhook"),
    re_path(r"^notifications/webhooks/(?P<nwhid>\d+)/edit$", views.EditNotificationWebhooksView.as_view(), name="edit_notification_webhook"),
    re_path(r"^notifications/webhooks/(?P<nwhid>\d+)/delete$", views.DeleteNotificationWebhooksView.as_view(), name="delete_notification_webhook"),
]
