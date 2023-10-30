from django.urls import re_path

from dojo.note_type import views

urlpatterns = [
    re_path(r'^note_type$',
        views.note_type, name='note_type'),
    re_path(r'^note/type/(?P<ntid>\d+)/edit$',
        views.edit_note_type, name='edit_note_type'),
    re_path(r'^note/type/(?P<ntid>\d+)/disable$',
        views.disable_note_type, name='disable_note_type'),
    re_path(r'^note/type/(?P<ntid>\d+)/enable$',
        views.enable_note_type, name='enable_note_type'),
    re_path(r'^add_note_type$',
        views.add_note_type, name='add_note_type'),
]
