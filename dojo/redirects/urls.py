from django.urls import path

from dojo.redirects import views

urlpatterns = [
    # some prefixs in the url path are duplicated, can't find a way to resuse them in django
    # ideally we want to just match the first part and then use the remainder in the redirect
    # is /s/product/name/pname/xxxx/yyyy/zzzz redirect to /product/id/xxxx/yyyy/zzzz

    # find product
    path('s/product/name/<str:pname>', views.view_product_by_name,
        name='view_product_by_name'),
    path('s/product/meta/<str:pmeta_name>/<str:pmeta_value>', views.view_product_by_meta,
        name='view_product_by_meta'),

    # cicd engagements inside product
    path('s/product/name/<str:pname>/engagements/cicd', views.view_cicd_engagements_by_product_by_name,
        name='view_cicd_engagements_by_product_by_name'),
    path('s/product/meta/<str:pmeta_name>/<str:pmeta_value>/engagements/cicd', views.view_cicd_engagements_by_product_by_meta,
        name='view_cicd_engagements_by_product_by_meta'),

    # find engagement inside product
    path('s/product/meta/<str:pmeta_name>/<str:pmeta_value>/engagement/name/<str:ename>', views.view_engagement_by_name_by_product_name,
        name='view_engagement_by_name_by_product_name'),
    path('s/product/meta/<str:pmeta_name>/<str:pmeta_value>/engagement/branch_tag/<str:btname>', views.view_engagement_by_branch_tag_by_product_name,
        name='view_engagement_by_branch_tag_by_product_name'),


]
