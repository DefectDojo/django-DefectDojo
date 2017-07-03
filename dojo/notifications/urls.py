from django.conf.urls import url
from django.contrib import admin
from django.apps import apps
import views

urlpatterns = [
    url(r'^notifications$', views.notifications, name='notifications')
    ]
