from django.urls import re_path
from . import views

urlpatterns = [
    re_path(r'^notifications$', views.PersonalNotificationsView.as_view(), name='notifications'),
    re_path(r'^notifications/system$', views.SystemNotificationsView.as_view(), name='system_notifications'),
    re_path(r'^notifications/personal$', views.PersonalNotificationsView.as_view(), name='personal_notifications'),
    re_path(r'^notifications/template$', views.TemplateNotificationsView.as_view(), name='template_notifications')
]
