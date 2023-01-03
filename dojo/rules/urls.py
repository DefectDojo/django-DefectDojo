from django.urls import re_path
from dojo.rules import views

urlpatterns = [
    re_path(r'^rules', views.rules, name='rules'),
    re_path(r'^rule/add', views.new_rule, name='Add Rule'),
    re_path(r'^rule/(?P<pid>\d+)/edit$', views.edit_rule,
        name='Edit Rule'),
    re_path(r'^rule/(?P<pid>\d+)/add_child', views.add_child,
        name='Add Child'),
    re_path(r'^rule/(?P<tid>\d+)/delete$', views.delete_rule,
        name='Delete Rule'), ]
