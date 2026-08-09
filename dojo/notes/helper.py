import logging

from django.db.models import Prefetch, Q

from dojo.notes.models import NoteHistory, Notes

logger = logging.getLogger(__name__)


def notes_prefetch(lookup="notes"):
    """
    Prefetch for relations rendered by NoteSerializer.

    NoteSerializer renders author/editor/note_type on each note and
    current_editor/note_type on each history entry; a flat prefetch of the
    notes relation leaves those to lazy-load with one query per object (N+1).
    """
    return Prefetch(
        lookup,
        queryset=Notes.objects.select_related("author", "editor", "note_type").prefetch_related(
            Prefetch("history", queryset=NoteHistory.objects.select_related("current_editor", "note_type")),
        ),
    )


def visible_notes(notes, user):
    """
    The notes ``user`` may see: non-private, or ones they wrote themselves.

    Every read path goes through here, so the API and the UI cannot drift apart
    on what ``private`` means. A caller with no user (report rendering) gets the
    non-private notes only.

    ``notes`` is usually a queryset, but DRF pagination evaluates the queryset
    before serialization and hands the note serializer the page as a plain
    ``list``, which has no ``filter``. Apply the same rule to either form so a
    paginated read does not 500 for a non-superuser.
    """
    if user is not None and user.is_superuser:
        return notes
    if hasattr(notes, "filter"):
        if user is None:
            return notes.filter(private=False)
        return notes.filter(Q(private=False) | Q(author=user))
    # An already-evaluated collection (e.g. a pagination page): filter in Python.
    if user is None:
        return [note for note in notes if not note.private]
    return [note for note in notes if not note.private or note.author_id == user.pk]


def delete_related_notes(obj):
    if not hasattr(obj, "notes"):
        logger.warning(f"Attempted to delete notes from object type {type(obj)} without 'notes' attribute.")
        return
    logger.debug(f"Deleting {obj.notes.count()} notes for {type(obj).__name__} {obj.id}")
    obj.notes.all().delete()
