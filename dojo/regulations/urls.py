from django.conf.urls import url
from django.contrib import admin
from django.apps import apps
from . import views

urlpatterns = [
    url(r'^regulations/add', views.new_regulation, name='add_regulations'),
    url(r'^regulations/(?P<ttid>\d+)/edit$', views.edit_regulations,
        name='edit_regulations'),
    url(r'^regulations$', views.regulations, name='regulations'), ]
