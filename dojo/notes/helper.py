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

    ``notes`` is not always a queryset. ``VisibleNotesSerializer`` filters
    whatever DRF hands its ``ListSerializer``, and on a list endpoint that is a
    plain list: ``paginate_queryset`` returns ``list(queryset[offset:limit])``.
    So the same rule is applied in Python when there is no queryset left to
    apply it to in SQL. Filtering a page after the fact does shorten it, which
    is a consequence of choosing to enforce the rule at serialization time; the
    alternative -- leaking another user's private note -- is worse.
    """
    if user is not None and user.is_superuser:
        return notes
    if not hasattr(notes, "filter"):
        return [
            note
            for note in notes
            if not note.private or (user is not None and note.author_id == user.pk)
        ]
    if user is None:
        return notes.filter(private=False)
    return notes.filter(Q(private=False) | Q(author=user))


def delete_related_notes(obj):
    if not hasattr(obj, "notes"):
        logger.warning(f"Attempted to delete notes from object type {type(obj)} without 'notes' attribute.")
        return
    logger.debug(f"Deleting {obj.notes.count()} notes for {type(obj).__name__} {obj.id}")
    obj.notes.all().delete()
