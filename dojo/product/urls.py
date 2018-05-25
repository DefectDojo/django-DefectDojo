from django.conf.urls import url

from dojo.product import views

urlpatterns = [
    #  product
    url(r'^product$', views.product, name='product'),
    url(r'^product/(?P<pid>\d+)$', views.view_product,
        name='view_product'),
    url(r'^product/(?P<pid>\d+)/engagements$', views.view_engagements,
        name='view_engagements'),
    url(r'^product/(?P<pid>\d+)/metrics$', views.view_product_metrics,
        name='view_product_metrics'),
    url(r'^product/(?P<pid>\d+)/details$', views.view_product_details,
        name='view_product_details'),
    url(r'^product/(?P<pid>\d+)/edit$', views.edit_product,
        name='edit_product'),
    url(r'^product/(?P<pid>\d+)/delete$', views.delete_product,
        name='delete_product'),
    url(r'^product/add', views.new_product, name='new_product'),
    url(r'^product/(?P<pid>\d+)/findings$',
        views.all_product_findings, name='view_product_findings'),
    url(r'^product/(?P<pid>\d+)/new_engagement$', views.new_eng_for_app,
        name='new_eng_for_prod'),
    url(r'^product/(?P<pid>\d+)/add_meta_data', views.add_meta_data,
        name='add_meta_data'),
    url(r'^product/(?P<pid>\d+)/edit_meta_data', views.edit_meta_data,
        name='edit_meta_data'),
    url(r'^product/(?P<pid>\d+)/ad_hoc_finding', views.ad_hoc_finding,
        name='ad_hoc_finding'),
]
