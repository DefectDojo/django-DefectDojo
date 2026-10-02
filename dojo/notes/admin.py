from django.contrib import admin

from dojo.notes.models import NoteHistory, Notes

admin.site.register(Notes)
admin.site.register(NoteHistory)
