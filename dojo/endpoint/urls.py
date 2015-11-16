from django.conf.urls import url

from dojo.endpoint import views

urlpatterns = [
    # endpoints
    url(r'^endpoint$', views.all_endpoints,
        name='endpoints'),
    url(r'^endpoint/vulnerable$', views.vulnerable_endpoints,
        name='vulnerable_endpoints'),
    url(r'^endpoint/(?P<eid>\d+)$', views.view_endpoint,
        name='view_endpoint'),
    url(r'^endpoint/(?P<eid>\d+)/edit$', views.edit_endpoint,
        name='edit_endpoint'),
    url(r'^endpoints/(?P<pid>\d+)/add$', views.add_endpoint,
        name='add_endpoint'),
    url(r'^endpoint/(?P<eid>\d+)/delete$', views.delete_endpoint,
        name='delete_endpoint'),
    url(r'^endpoints/add$', views.add_product_endpoint,
        name='add_product_endpoint'),
]