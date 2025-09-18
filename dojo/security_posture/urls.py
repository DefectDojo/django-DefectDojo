from django.urls import re_path
from dojo.security_posture import views

urlpatterns = [
    re_path(
        r"^engagement/security_posture/$",
        views.security_posture,
        name="security_posture"
    )
]