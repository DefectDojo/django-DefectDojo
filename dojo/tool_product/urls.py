from django.urls import re_path
from . import views

urlpatterns = [
    re_path(r'^product/(?P<pid>\d+)/tool_product/add$', views.new_tool_product, name='new_tool_product'),
    re_path(r'^product/(?P<pid>\d+)/tool_product/all$', views.all_tool_product, name='all_tool_product'),
    re_path(r'^product/(?P<pid>\d+)/tool_product/(?P<ttid>\d+)/edit$', views.edit_tool_product, name='edit_tool_product'),
    re_path(r'^product/(?P<pid>\d+)/tool_product/(?P<ttid>\d+)/delete$', views.delete_tool_product,
        name='delete_tool_product'),
]
