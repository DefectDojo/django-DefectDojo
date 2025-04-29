from django.urls import re_path

from dojo.home import views

urlpatterns = [
    #  dojo home pages
    re_path(r"^$", views.home, name="home"),
    re_path(r"^dashboard_v1$", views.dashboard, name="dashboard_v1"),
    re_path(r"^dashboard$", views.dashboard_v2, name="dashboard"),
    re_path(r"^support$", views.support, name="support"),
]
