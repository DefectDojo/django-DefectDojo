from django.conf.urls import url
from django.contrib import admin
from django.apps import apps
import views

urlpatterns = [
    url(r'^system_settings$', views.system_settings, name='system_settings')
    ]
