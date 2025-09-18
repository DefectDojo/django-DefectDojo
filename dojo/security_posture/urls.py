from django.urls import re_path
from dojo.security_posture import views

urlpatterns = [
    re_path(
        r"^engagement/security_posture/$",
        views.security_posture_view,
        name="security_posture_view"
    )
]