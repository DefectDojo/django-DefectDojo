from django.urls import re_path

from dojo.announcement.ui import views

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
    re_path(
        r"^dismiss_os_message$",
        views.dismiss_os_message,
        name="dismiss_os_message",
    ),
    re_path(
        r"^github_star_prompt$",
        views.github_star_prompt,
        name="github_star_prompt",
    ),
]
