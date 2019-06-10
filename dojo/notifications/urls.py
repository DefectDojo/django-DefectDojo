from django.conf.urls import url
from django.contrib import admin
from django.apps import apps
from . import views

urlpatterns = [
    url(r'^notifications$', views.personal_notifications, name='notifications'),
    url(r'^notifications/global$', views.global_notifications, name='notifications'),
    url(r'^notifications/personal$', views.personal_notifications, name='notifications')
    ]
