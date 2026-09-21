from django.urls import re_path

from dojo.product_attributes.ui import views

urlpatterns = [
    # platforms
    re_path(r"^product_platform$", views.list_platforms, name="product_platforms"),
    re_path(r"^product_platform/add$", views.add_platform, name="add_product_platform"),
    re_path(r"^product_platform/(?P<pk>\d+)/edit$", views.edit_platform, name="edit_product_platform"),
    # lifecycles
    re_path(r"^product_lifecycle$", views.list_lifecycles, name="product_lifecycles"),
    re_path(r"^product_lifecycle/add$", views.add_lifecycle, name="add_product_lifecycle"),
    re_path(r"^product_lifecycle/(?P<pk>\d+)/edit$", views.edit_lifecycle, name="edit_product_lifecycle"),
    # origins
    re_path(r"^product_origin$", views.list_origins, name="product_origins"),
    re_path(r"^product_origin/add$", views.add_origin, name="add_product_origin"),
    re_path(r"^product_origin/(?P<pk>\d+)/edit$", views.edit_origin, name="edit_product_origin"),
]
