from django.apps import apps
from django.contrib import admin
from dojo.engine_tools import views
from django.urls import re_path, path

if not apps.ready:
    apps.get_models()

admin.autodiscover()

urlpatterns = [
    re_path(r"^engine_tools/finding_exclusions$",
            views.finding_exclusions,
            name="finding_exclusions"),
    re_path(r"^engine_tools/create_finding_exclusion$",
            views.create_finding_exclusion,
            name="create_finding_exclusion"),
    re_path(r"^engine_tools/finding_exclusion/(?P<fxid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
            views.show_finding_exclusion,
            name="finding_exclusion"),
    re_path(r'^engine_tools/finding-exclusion/(?P<fxid>[\w-]+)/add-discussion/$', 
            views.add_finding_exclusion_discussion, 
            name='add_finding_exclusion_discussion'),
    re_path(r'^engine_tools/finding-exclusion/(?P<fxid>[\w-]+)/mark-as-reviewed/$', 
            views.review_finding_exclusion_request, 
            name='review_finding_exclusion_request'),
    re_path(r'^engine_tools/finding-exclusion/(?P<fxid>[\w-]+)/mark-as-accepted/$', 
            views.accept_finding_exclusion_request, 
            name='accept_finding_exclusion_request'),
    re_path(r'^engine_tools/finding-exclusion/(?P<fxid>[\w-]+)/mark-as-rejected/$', 
            views.reject_finding_exclusion_request, 
            name='reject_finding_exclusion_request'),
    re_path(r'^engine_tools/finding-exclusion/(?P<fxid>[\w-]+)/mark-as-expired/$', 
            views.expire_finding_exclusion_request, 
            name='expire_finding_exclusion_request'),
    re_path(r'^engine_tools/finding-exclusion/(?P<fxid>[\w-]+)/edit-exclusion/$', 
            views.edit_finding_exclusion_request, 
            name='edit_finding_exclusion_request'),
    re_path(r'^engine_tools/finding-exclusion/(?P<fxid>[\w-]+)/edit/$', 
            views.edit_finding_exclusion, 
            name='edit_finding_exclusion'),
]