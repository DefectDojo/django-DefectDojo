from django.urls import re_path

from dojo.system_settings import views

urlpatterns = [
    re_path(
        r"^system_settings$",
        views.SystemSettingsView.as_view(),
        name="system_settings",
    ),
    re_path(
        r"^system_status$",
        views.SystemStatusView.as_view(),
        name="system_status",
    ),
]
