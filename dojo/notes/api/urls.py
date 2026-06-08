from dojo.notes.api import path
from dojo.notes.api.views import NotesViewSet


def add_notes_urls(router):
    router.register(path, NotesViewSet, basename="notes")
    return router
