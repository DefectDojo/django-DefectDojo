from django.urls import re_path
from . import views

urlpatterns = [
    re_path(r'^notifications$', views.personal_notifications, name='notifications'),
    re_path(r'^notifications/system$', views.system_notifications, name='system_notifications'),
    re_path(r'^notifications/personal$', views.personal_notifications, name='personal_notifications'),
    re_path(r'^notifications/template$', views.template_notifications, name='template_notifications')
]
