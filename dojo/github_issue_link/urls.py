from django.urls import re_path
from . import views

urlpatterns = [
    re_path(r'^github-webhook', views.webhook, name='github_web_hook'),
    re_path(r'^github/add', views.new_github, name='add_github'),
    re_path(r'^github/(?P<tid>\d+)/delete$', views.delete_github,
        name='delete_github'),
    re_path(r'^github$', views.github, name='github')]
