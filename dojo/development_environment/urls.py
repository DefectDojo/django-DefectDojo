from django.urls import re_path

from dojo.development_environment import views

urlpatterns = [
    # dev envs
    re_path(r'^dev_env$', views.dev_env, name='dev_env'),
    re_path(r'^dev_env/add$', views.add_dev_env,
        name='add_dev_env'),
    re_path(r'^dev_env/(?P<deid>\d+)/edit$',
        views.edit_dev_env, name='edit_dev_env'),
]
