from django.conf.urls import url

from dojo.group import views

urlpatterns = [
    url(r'^group$', views.group, name='groups'),
    url(r'^group/(?P<gid>\d+)$', views.view_group,
        name='view_group'),
    url(r'^group/(?P<gid>\d+)/edit$', views.edit_group,
        name='edit_group'),
    url(r'^group/(?P<gid>\d+)/delete', views.delete_group,
        name='delete_group'),
    url(r'^group/add$', views.add_group, name='add_group'),
    url(r'^group/(?P<gid>\d+)/add_product_group', views.add_product_group,
        name='add_product_group_group'),
    url(r'^group/(?P<gid>\d+)/add_product_type_group', views.add_product_type_group,
        name='add_product_type_group_group'),
    url(r'^group/(?P<gid>\d+)/add_group_member', views.add_group_member,
        name='add_group_member'),
    url(r'group/member/(?P<mid>\d+)/edit_group_member', views.edit_group_member,
        name='edit_group_member'),
    url(r'group/member/(?P<mid>\d+)/delete_group_member', views.delete_group_member,
        name='delete_group_member'),
    url(r'^group/(?P<gid>\d+)/edit_permissions$', views.edit_permissions,
        name='edit_group_permissions')
]
