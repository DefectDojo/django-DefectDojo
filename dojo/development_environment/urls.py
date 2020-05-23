from django.conf.urls import url

from dojo.development_environment import views

urlpatterns = [
    # dev envs
    url(r'^environment$', views.environment, name='environment'),
    url(r'^environment/add$', views.add_environment,
        name='add_environment'),
    url(r'^environment/(?P<deid>\d+)/edit$',
        views.edit_environment, name='edit_environment'),
]