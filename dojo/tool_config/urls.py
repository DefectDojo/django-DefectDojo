from django.conf.urls import patterns, url
from django.contrib import admin
from django.apps import apps
import views

urlpatterns = patterns(
'',
url(r'^tool_config/add', views.new_tool_config, name='add_tool_config'),
url(r'^tool_config/(?P<ttid>\d+)/edit$', views.edit_tool_config,
     name='edit_tool_config'),
url(r'^tool_config$', views.tool_config, name='tool_config'),)
