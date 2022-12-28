from django.urls import re_path
from . import views

urlpatterns = [
    re_path(r'^regulations/add', views.new_regulation, name='new_regulation'),
    re_path(r'^regulations/(?P<ttid>\d+)/edit$', views.edit_regulations,
        name='edit_regulations'),
    re_path(r'^regulations$', views.regulations, name='regulations'), ]
