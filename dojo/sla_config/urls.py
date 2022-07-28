from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^sla_config/add', views.new_sla_config, name='new_sla_config'),
    url(r'^sla_config/(?P<slaid>\d+)/edit$', views.edit_sla_config, name='edit_sla_config'),
    url(r'^sla_config$', views.sla_config, name='sla_config'),
]
