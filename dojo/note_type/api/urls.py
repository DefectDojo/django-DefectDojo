from dojo.note_type.api import path
from dojo.note_type.api.views import NoteTypeViewSet


def add_note_type_urls(router):
    router.register(path, NoteTypeViewSet, basename="note_type")
    return router
