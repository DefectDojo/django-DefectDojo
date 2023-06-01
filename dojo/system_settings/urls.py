from django.urls import re_path
from . import views

urlpatterns = [
    re_path(r'^system_settings$', views.system_settings, name='system_settings')
]
