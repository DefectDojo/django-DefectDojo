import logging

from django.db.models.signals import pre_delete
from django.dispatch import receiver

from dojo.models import Notes
from dojo.notes.helper import is_note_history_deleted_by_caller

logger = logging.getLogger(__name__)


def delete_note_history(note):
    logger.debug(f"Deleting history for note {note.id}")
    note.history.all().delete()


@receiver(pre_delete, sender=Notes)
def note_pre_delete(sender, instance, **kwargs):
    # delete_related_notes deletes a whole batch's history itself, in one query.
    if is_note_history_deleted_by_caller():
        return
    delete_note_history(instance)
