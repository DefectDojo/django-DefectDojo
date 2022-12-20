from django.urls import re_path
from dojo.banner import views

urlpatterns = [
    re_path(r'^configure_banner$', views.configure_banner,
     name='configure_banner'),
]
