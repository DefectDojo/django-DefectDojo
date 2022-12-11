from django.urls import re_path

from dojo.group import views

urlpatterns = [
    re_path(r'^group$', views.group, name='groups'),
    re_path(r'^group/(?P<gid>\d+)$', views.view_group, name='view_group'),
    re_path(r'^group/(?P<gid>\d+)/edit$', views.edit_group, name='edit_group'),
    re_path(r'^group/(?P<gid>\d+)/delete', views.delete_group, name='delete_group'),
    re_path(r'^group/add$', views.add_group, name='add_group'),
    re_path(r'^group/(?P<gid>\d+)/add_product_group', views.add_product_group, name='add_product_group_group'),
    re_path(r'^group/(?P<gid>\d+)/add_product_type_group', views.add_product_type_group, name='add_product_type_group_group'),
    re_path(r'^group/(?P<gid>\d+)/add_group_member', views.add_group_member, name='add_group_member'),
    re_path(r'group/member/(?P<mid>\d+)/edit_group_member', views.edit_group_member, name='edit_group_member'),
    re_path(r'group/member/(?P<mid>\d+)/delete_group_member', views.delete_group_member, name='delete_group_member'),
    re_path(r'^group/(?P<gid>\d+)/edit_permissions$', views.edit_permissions, name='edit_group_permissions')
]
