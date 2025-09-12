from django.urls import re_path

from dojo.product import views as product_views
from dojo.product_type import views
from dojo.v3_migration import redirect_view

common_urlpatterns = []


v2_urlpatterns = [
    re_path(r"^product/type$", views.product_type, name="product_type"),
    re_path(r"^product/type/(?P<ptid>\d+)$",
            views.view_product_type, name="view_product_type"),
    re_path(r"^product/type/(?P<ptid>\d+)/edit$",
            views.edit_product_type, name="edit_product_type"),
    re_path(r"^product/type/(?P<ptid>\d+)/delete$",
            views.delete_product_type, name="delete_product_type"),
    re_path(r"^product/type/add$", views.add_product_type,
            name="add_product_type"),
    re_path(r"^product/type/(?P<ptid>\d+)/add_product",
            product_views.new_product,
            name="add_product_to_product_type"),
    re_path(r"^product/type/(?P<ptid>\d+)/add_member$", views.add_product_type_member,
            name="add_product_type_member"),
    re_path(r"^product/type/member/(?P<memberid>\d+)/edit$", views.edit_product_type_member,
            name="edit_product_type_member"),
    re_path(r"^product/type/member/(?P<memberid>\d+)/delete$", views.delete_product_type_member,
            name="delete_product_type_member"),
    re_path(r"^product/type/(?P<ptid>\d+)/add_group$", views.add_product_type_group,
            name="add_product_type_group"),
    re_path(r"^product/type/group/(?P<groupid>\d+)/edit$", views.edit_product_type_group,
            name="edit_product_type_group"),
    re_path(r"^product/type/group/(?P<groupid>\d+)/delete$", views.delete_product_type_group,
            name="delete_product_type_group"),
]


v3_forward_urlpatterns = [
    re_path(r"^organization$", redirect_view("product_type")),
    re_path(r"^organization/(?P<ptid>\d+)$", redirect_view("view_product_type")),
    re_path(r"^organization/(?P<ptid>\d+)/edit$", redirect_view("edit_product_type")),
    re_path(r"^organization/(?P<ptid>\d+)/delete$", redirect_view("delete_product_type")),
    re_path(r"^organization/add$", redirect_view("add_product_type")),
    re_path(r"^organization/(?P<ptid>\d+)/add_asset", redirect_view("add_product_to_product_type")),
    re_path(r"^organization/(?P<ptid>\d+)/add_member$", redirect_view("add_product_type_member")),
    re_path(r"^organization/member/(?P<memberid>\d+)/edit$", redirect_view("edit_product_type_member")),
    re_path(r"^organization/member/(?P<memberid>\d+)/delete$", redirect_view("delete_product_type_member")),
    re_path(r"^organization/(?P<ptid>\d+)/add_group$", redirect_view("add_product_type_group")),
    re_path(r"^organization/group/(?P<groupid>\d+)/edit$", redirect_view("edit_product_type_group")),
    re_path(r"^organization/group/(?P<groupid>\d+)/delete$", redirect_view("delete_product_type_group")),
]


urlpatterns = common_urlpatterns + v2_urlpatterns + v3_forward_urlpatterns
