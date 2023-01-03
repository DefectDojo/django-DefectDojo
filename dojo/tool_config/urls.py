from django.urls import re_path
from . import views

urlpatterns = [
    re_path(r'^tool_config/add', views.new_tool_config, name='add_tool_config'),
    re_path(r'^tool_config/(?P<ttid>\d+)/edit$', views.edit_tool_config,
        name='edit_tool_config'),
    re_path(r'^tool_config$', views.tool_config, name='tool_config'),
]
