from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^notes/(?P<id>\d+)/delete/(?P<page>[\w-]+)/(?P<objid>\d+)$', views.delete_issue, name='delete_note'), ]
