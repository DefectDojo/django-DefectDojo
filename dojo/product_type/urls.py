from django.conf.urls import url

from dojo.product_type import views
from dojo.product import views as product_views

urlpatterns = [
    #  product type
    url(r'^product/type$', views.product_type, name='product_type'),
    url(r'^product/type/(?P<ptid>\d+)/edit$',
        views.edit_product_type, name='edit_product_type'),
    url(r'^product/type/add$', views.add_product_type,
        name='add_product_type'),
    url(r'^product/type/(?P<ptid>\d+)/add_product',
        product_views.new_product,
        name='add_product_to_product_type'),
]
