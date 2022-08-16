from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^notifications$', views.personal_notifications, name='notifications'),
    url(r'^notifications/system$', views.system_notifications, name='system_notifications'),
    url(r'^notifications/personal$', views.personal_notifications, name='personal_notifications'),
    url(r'^notifications/template$', views.template_notifications, name='template_notifications')
]
