from django.urls import re_path

from dojo.product_type import views
from dojo.product import views as product_views

urlpatterns = [
    #  product type
    re_path(r'^product/type$', views.product_type, name='product_type'),
    re_path(r'^product/type/(?P<ptid>\d+)$',
        views.view_product_type, name='view_product_type'),
    re_path(r'^product/type/(?P<ptid>\d+)/edit$',
        views.edit_product_type, name='edit_product_type'),
    re_path(r'^product/type/(?P<ptid>\d+)/delete$',
        views.delete_product_type, name='delete_product_type'),
    re_path(r'^product/type/add$', views.add_product_type,
        name='add_product_type'),
    re_path(r'^product/type/(?P<ptid>\d+)/add_product',
        product_views.new_product,
        name='add_product_to_product_type'),
    re_path(r'^product/type/(?P<ptid>\d+)/add_member$', views.add_product_type_member,
        name='add_product_type_member'),
    re_path(r'^product/type/member/(?P<memberid>\d+)/edit$', views.edit_product_type_member,
        name='edit_product_type_member'),
    re_path(r'^product/type/member/(?P<memberid>\d+)/delete$', views.delete_product_type_member,
        name='delete_product_type_member'),
    re_path(r'^product/type/(?P<ptid>\d+)/add_group$', views.add_product_type_group,
        name='add_product_type_group'),
    re_path(r'^product/type/group/(?P<groupid>\d+)/edit$', views.edit_product_type_group,
        name='edit_product_type_group'),
    re_path(r'^product/type/group/(?P<groupid>\d+)/delete$', views.delete_product_type_group,
        name='delete_product_type_group')
]
