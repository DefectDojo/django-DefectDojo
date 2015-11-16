from django.conf.urls import url

from dojo.product import views

urlpatterns = [
    #  product
    url(r'^product$', views.product, name='product'),
    url(r'^product/(?P<pid>\d+)$', views.view_product,
        name='view_product'),
    url(r'^product/(?P<pid>\d+)/edit$', views.edit_product,
        name='edit_product'),
    url(r'^product/(?P<pid>\d+)/delete$', views.delete_product,
        name='delete_product'),
    url(r'^product/add', views.new_product, name='new_product'),
    url(r'^product/(?P<pid>\d+)/findings$',
        views.all_product_findings, name='view_product_findings'),
    url(r'^product/(?P<pid>\d+)/new_engagement$', views.new_eng_for_app,
        name='new_eng_for_prod'),
]