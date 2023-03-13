from django.urls import re_path
from . import views

urlpatterns = [
    re_path(r'^api_scan_configurations$', views.api_scan_configurations, name='api_scan_configurations'),
]
