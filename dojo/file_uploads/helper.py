import logging

logger = logging.getLogger(__name__)


def delete_related_files(obj):
    if not hasattr(obj, "files"):
        logger.warning(f"Attempted to delete files from object type {type(obj)} without 'files' attribute.")
        return
    logger.debug(f"Deleting {obj.files.count()} files for {type(obj).__name__} {obj.id}")
    obj.files.all().delete()
