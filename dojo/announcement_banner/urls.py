from django.conf.urls import url
from dojo.announcement_banner import views

urlpatterns = [
    url(r'^configure_announcement_banner$', views.configure_announcement_banner,
     name='configure_announcement_banner'),
]
