from django.conf import settings
from django.conf.urls import include
from django.urls import re_path

urlpatterns = [
    re_path("", include("social_django.urls", namespace="social")),
]

if getattr(settings, "SAML2_ENABLED", False):
    urlpatterns += [re_path(r"^saml2/", include("djangosaml2.urls"))]
