from django.urls import re_path
from . import views

urlpatterns = [
    re_path(r'^dedupe_config/add', views.new_dedupe_config, name='add_dedupe_config'),
    re_path(r'^dedupe_config/(?P<ttid>\d+)/edit$', views.edit_dedupe_config,
        name='edit_dedupe_config'),
    re_path(r'^dedupe_config$', views.dedupe_config, name='dedupe_config'),
]
