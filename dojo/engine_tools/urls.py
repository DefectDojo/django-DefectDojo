from django.apps import apps
from django.contrib import admin
from dojo.engine_tools import views
from django.urls import re_path, path

if not apps.ready:
    apps.get_models()

admin.autodiscover()

urlpatterns = [
    re_path(r"^engine_tools/finding_exclusions$",
            views.finding_exclusion,
            name="finding_exclusion"),
    re_path(r"^engine_tools/create_finding_exclusion$",
            views.create_finding_exclusion,
            name="create_finding_exclusion"),
    re_path(r"^engine_tools/finding_exclusion/(?P<fxid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
            views.show_finding_exclusion,
            name="finding_exclusion")
]