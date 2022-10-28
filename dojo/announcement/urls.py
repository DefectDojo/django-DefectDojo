from django.conf.urls import url
from dojo.announcement import views

urlpatterns = [
    url(r'^configure_announcement$', views.configure_announcement,
     name='configure_announcement'),
    url(r'^dismiss_announcement$', views.dismiss_announcement,
     name='dismiss_announcement'),
]
