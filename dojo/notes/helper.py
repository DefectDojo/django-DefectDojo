import logging

from django.db.models.signals import pre_delete
from django.dispatch import receiver

logger = logging.getLogger(__name__)


def delete_related_notes(obj):
    if not hasattr(obj, 'notes'):
        logger.warning(f"Attempted to delete notes from object type {type(obj)} without 'notes' attribute.")
        return
    logging.debug(f"Deleting {obj.notes.count()} notes for {type(obj).__name__} {obj.id}")
    obj.notes.all().delete()


def generate_pre_delete_notes_cleanup(model):
    if not hasattr(model, 'notes'):
        logger.warning(
            f"Attempting to generate notes deleter for model {model.__name__} which has no 'notes' attribute.")
        return None

    @receiver(pre_delete, sender=model)
    def model_pre_delete(sender, instance, **kwargs):
        logging.debug(f"Deleting notes for {model.__name__} {instance.id}")
        delete_related_notes(instance)

    return model_pre_delete
