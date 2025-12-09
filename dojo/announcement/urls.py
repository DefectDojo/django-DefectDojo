from django.urls import re_path

from dojo.announcement import views

urlpatterns = [
    re_path(
        r"^configure_announcement$",
        views.configure_announcement,
        name="configure_announcement",
    ),
    re_path(
        r"^dismiss_announcement$",
        views.dismiss_announcement,
        name="dismiss_announcement",
    ),
]
