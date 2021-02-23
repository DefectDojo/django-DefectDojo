from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^system_settings$', views.system_settings, name='system_settings')
]
