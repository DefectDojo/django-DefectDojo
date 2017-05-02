from django.conf.urls import patterns, url
from django.contrib import admin
from django.apps import apps
import views

urlpatterns = patterns(
'',
url(r'^tool_type/add', views.new_tool_type, name='add_tool_type'),
url(r'^tool_type/(?P<ttid>\d+)/edit$', views.edit_tool_type,
     name='edit_tool_type'),
url(r'^tool_type$', views.tool_type, name='tool_type'),)
