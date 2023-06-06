from django.urls import re_path
from . import views

urlpatterns = [
    re_path(r'^sla_config/add', views.new_sla_config, name='new_sla_config'),
    re_path(r'^sla_config/(?P<slaid>\d+)/edit$', views.edit_sla_config, name='edit_sla_config'),
    re_path(r'^sla_config$', views.sla_config, name='sla_config'),
]
