from django.urls import path

from dojo.redirects import views

urlpatterns = [
    path('s/product/name/<str:pname>', views.view_product_by_name,
        name='view_product_by_name'),
    path('s/product/meta/<str:pmeta_name>/<str:pmeta_value>', views.view_product_by_meta,
        name='view_product_by_meta'),
    path('s/product/meta/<str:pmeta_name>/<str:pmeta_value>/engagement/name/<str:ename>', views.view_engagement_by_name_by_product_name,
        name='view_engagement_by_name_by_product_name'),
    path('s/product/meta/<str:pmeta_name>/<str:pmeta_value>/engagement/branch_tag/<str:btname>', views.view_engagement_by_branch_tag_by_product_name,
        name='view_engagement_by_branch_tag_by_product_name'),


]
