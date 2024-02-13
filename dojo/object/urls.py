from django.urls import re_path
from . import views

urlpatterns = [
    re_path(r'^product/(?P<pid>\d+)/object/add$', views.new_object, name='new_object'),
    re_path(r'^product/(?P<pid>\d+)/object/(?P<ttid>\d+)/edit$', views.edit_object, name='edit_object'),
    re_path(r'^product/(?P<pid>\d+)/object/view$', views.view_objects, name='view_objects'),
    re_path(r'^product/(?P<pid>\d+)/object/(?P<ttid>\d+)/delete$', views.delete_object,
        name='delete_object'),
]
