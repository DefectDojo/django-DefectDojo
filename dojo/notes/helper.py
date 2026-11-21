import logging
from contextlib import contextmanager
from contextvars import ContextVar

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
    apply it to in SQL, and also when the queryset is a prefetched relation
    whose rows are already loaded. Filtering a page after the fact does shorten it, which
    is a consequence of choosing to enforce the rule at serialization time; the
    alternative -- leaking another user's private note -- is worse.
    """
    if user is not None and user.is_superuser:
        return notes
    # A prefetched relation has its rows loaded already: filtering it in SQL would discard them,
    # and the prefetch of their history with them, costing two queries per object on a list page.
    if not hasattr(notes, "filter") or getattr(notes, "_result_cache", None) is not None:
        return [
            note
            for note in notes
            if not note.private or (user is not None and note.author_id == user.pk)
        ]
    if user is None:
        return notes.filter(private=False)
    return notes.filter(Q(private=False) | Q(author=user))


def delete_related_notes(obj):
    """
    Delete ``obj``'s notes and their edit history in a fixed number of queries, however many notes there are.

    A note's history rows belong to that note alone (``Notes.copy`` copies them), so they go with it. The per-note
    ``pre_delete`` receiver (dojo.notes.signals) deletes them one note at a time, about four queries per note, which
    made deleting a finding with a hundred notes cost some 500 queries. Here every history row is read once, the notes
    are deleted with that receiver standing down, and the history rows are deleted in one batch.
    """
    if not hasattr(obj, "notes"):
        logger.warning(f"Attempted to delete notes from object type {type(obj)} without 'notes' attribute.")
        return
    note_ids = list(obj.notes.values_list("id", flat=True))
    logger.debug("Deleting %d notes for %s %s", len(note_ids), type(obj).__name__, obj.id)
    if not note_ids:
        return
    history_ids = list(Notes.history.through.objects.filter(notes__in=note_ids).values_list("notehistory_id", flat=True))
    with note_history_deleted_by_caller():
        Notes.objects.filter(id__in=note_ids).delete()
    if history_ids:
        NoteHistory.objects.filter(id__in=history_ids).delete()


_note_history_deleted_by_caller = ContextVar("note_history_deleted_by_caller", default=False)


@contextmanager
def note_history_deleted_by_caller():
    """Notes deleted inside this block leave their history to the caller, which deletes it in one batch."""
    token = _note_history_deleted_by_caller.set(True)
    try:
        yield
    finally:
        _note_history_deleted_by_caller.reset(token)


def is_note_history_deleted_by_caller() -> bool:
    return _note_history_deleted_by_caller.get()
