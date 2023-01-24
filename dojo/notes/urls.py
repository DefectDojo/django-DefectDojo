from django.urls import re_path
from . import views

urlpatterns = [
    re_path(r'^notes/(?P<id>\d+)/delete/(?P<page>[\w-]+)/(?P<objid>\d+)$', views.delete_note, name='delete_note'),
    re_path(r'^notes/(?P<id>\d+)/edit/(?P<page>[\w-]+)/(?P<objid>\d+)$', views.edit_note, name='edit_note'),
    re_path(r'^notes/(?P<id>\d+)/history/(?P<page>[\w-]+)/(?P<objid>\d+)$', views.note_history, name='note_history')
                ]
