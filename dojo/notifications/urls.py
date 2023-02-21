from django.urls import re_path

from . import views

urlpatterns = [
    re_path(r"^notifications$", views.PersonalNotificationsView.as_view(), name="notifications"),
    re_path(r"^notifications/system$", views.SystemNotificationsView.as_view(), name="system_notifications"),
    re_path(r"^notifications/personal$", views.PersonalNotificationsView.as_view(), name="personal_notifications"),
    re_path(r"^notifications/template$", views.TemplateNotificationsView.as_view(), name="template_notifications"),
    re_path(r'^notifications/webhooks$', views.notification_webhooks, name='notification_webhooks'),
    re_path(r'^notifications/webhooks/add$', views.add_notification_webhook, name='add_notification_webhook'),
    re_path(r'^notifications/webhooks/(?P<nwhid>\d+)/edit$', views.edit_notification_webhook, name='edit_notification_webhook'),
    re_path(r'^notifications/webhooks/(?P<nwhid>\d+)/delete$', views.delete_notification_webhook, name='delete_notification_webhook'),
    # re_path(r'^notifications/webhooks/(?P<nwhid>\d+)/activate$', views.activate_notification_webhook, name='activate_notification_webhook'), # TODO finish
    # re_path(r'^notifications/webhooks/(?P<nwhid>\d+)/deactivate$', views.deactivate_notification_webhook, name='deactivate_notification_webhook'),
]
