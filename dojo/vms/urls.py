from django.conf.urls import url

from dojo.vms import views

urlpatterns = [
    #  engagements and calendar
    url(r'^vm$', views.vm, name='vm'),
    url(r'^vm/new$', views.new_vm, name='new_vm'),
    url(r'^vm/(?P<id>\d+)$', views.view_vm,
        name='view_vm'),
    url(r'^vm/(?P<id>\d+)/edit$', views.edit_vm,
        name='edit_vm'),
    url(r'^vm/(?P<id>\d+)/delete$', views.delete_vm,
        name='delete_vm'),
    url(r'^vm/(?P<id>\d+)/add_engagement$', views.add_vm_engagement,
        name='add_vm_engagement'),
    url(r'^vm/(?P<id>\d+)/delete_engagement$', views.delete_vm_engagement,
        name='delete_vm_engagement'),
]
