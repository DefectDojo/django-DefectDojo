from django.urls import re_path
from . import views

urlpatterns = [
    re_path(r'^tool_type/add', views.new_tool_type, name='add_tool_type'),
    re_path(r'^tool_type/(?P<ttid>\d+)/edit$', views.edit_tool_type,
        name='edit_tool_type'),
    re_path(r'^tool_type$', views.tool_type, name='tool_type'),
]
