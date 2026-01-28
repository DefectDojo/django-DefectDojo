import logging
import os
from logging.config import dictConfig

from celery import Celery, Task
from celery.signals import setup_logging
from django.conf import settings

logger = logging.getLogger(__name__)

# set the default Django settings module for the 'celery' program.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dojo.settings.settings")


class PgHistoryTask(Task):

    """
    Custom Celery base task that automatically applies pghistory context.

    When a task is dispatched via dojo_async_task, the current pghistory
    context is captured and passed in kwargs as "_pgh_context". This base
    class extracts that context and applies it before running the task,
    ensuring all database events share the same context as the original
    request.
    """

    def __call__(self, *args, **kwargs):
        # Import here to avoid circular imports during Celery startup
        from dojo.pghistory_utils import get_pghistory_context_manager  # noqa: PLC0415

        # Extract context from kwargs (won't be passed to task function)
        pgh_context = kwargs.pop("_pgh_context", None)

        with get_pghistory_context_manager(pgh_context):
            return super().__call__(*args, **kwargs)


app = Celery("dojo", task_cls=PgHistoryTask)

# Using a string here means the worker will not have to
# pickle the object when using Windows.
app.config_from_object("django.conf:settings", namespace="CELERY")

app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)


@app.task(bind=True)
def debug_task(self):
    logger.info(f"Request: {self.request!r}")


@setup_logging.connect
def config_loggers(*args, **kwags):
    dictConfig(settings.LOGGING)


# from celery import current_app

# _ = current_app.loader.import_default_modules()

# tasks = list(sorted(name for name in current_app.tasks
#                             if not name.startswith('celery.')))

# logger.debug('registered celery tasks:')
# for task in tasks:
#     logger.debug(task)
