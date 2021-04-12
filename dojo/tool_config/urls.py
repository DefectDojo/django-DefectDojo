from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^tool_config/add', views.new_tool_config, name='add_tool_config'),
    url(r'^tool_config/(?P<ttid>\d+)/edit$', views.edit_tool_config,
        name='edit_tool_config'),
    url(r'^tool_config$', views.tool_config, name='tool_config'),
]
