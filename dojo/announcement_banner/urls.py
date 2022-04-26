from django.conf.urls import url
from dojo.announcement_banner import views

urlpatterns = [
    url(r'^configure_announcement_banner$', views.configure_announcement_banner,
     name='configure_announcement_banner'),
    url(r'^dismiss_announcement_banner$', views.dismiss_announcement_banner,
     name='dismiss_announcement_banner'),
]
