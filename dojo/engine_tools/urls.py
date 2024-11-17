from django.apps import apps
from django.contrib import admin
from dojo.engine_tools import views
from django.urls import re_path

if not apps.ready:
    apps.get_models()

admin.autodiscover()

urlpatterns = [
    re_path(r"^engine_tools/finding_exclusion$",
            views.finding_exclusion,
            name="finding_exclusion"),
    re_path(r"^engine_tools/create_finding_exclusion$",
            views.create_finding_exclusion,
            name="create_finding_exclusion"),
    re_path(r"^engine_tools/edit_finding_exclusion$",
            views.finding_exclusion,
            name="finding_exclusion"),
    re_path(r"^engine_tools/delete_finding_exclusion$",
            views.finding_exclusion,
            name="finding_exclusion"),
    re_path(r"^engine_tools/show_finding_exclusion/(?P<fxid>\d+)$",
            views.show_find_exclusion,
            name="show_finding_exclusion"),
]