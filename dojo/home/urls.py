from django.urls import re_path

from dojo.home import views

urlpatterns = [
    #  dojo home pages
    re_path(r'^$', views.home, name='home'),
    re_path(r'^dashboard$', views.dashboard, name='dashboard'),
]
