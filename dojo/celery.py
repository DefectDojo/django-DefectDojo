import logging
import os
from logging.config import dictConfig

from celery import Celery, Task
from celery.signals import setup_logging
from django.conf import settings

logger = logging.getLogger(__name__)

# set the default Django settings module for the 'celery' program.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dojo.settings.settings")

app = Celery("dojo")

# Using a string here means the worker will not have to
# pickle the object when using Windows.
app.config_from_object("django.conf:settings", namespace="CELERY")

app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)


class DojoAsyncTask(Task):

    """
    Base task class that provides dojo_async_task functionality without using a decorator.

    This class:
    - Injects user context into task kwargs
    - Tracks task calls for performance testing
    - Supports all Celery features (signatures, chords, groups, chains)
    """

    def apply_async(self, args=None, kwargs=None, **options):
        """Override apply_async to inject user context and track tasks."""
        from dojo.decorators import dojo_async_task_counter  # noqa: PLC0415 circular import
        from dojo.utils import get_current_user  # noqa: PLC0415 circular import

        if kwargs is None:
            kwargs = {}

        # Inject user context if not already present
        if "async_user" not in kwargs:
            kwargs["async_user"] = get_current_user()

        # Control flag used for sync/async decision; never pass into the task itself
        kwargs.pop("sync", None)

        # Track dispatch
        dojo_async_task_counter.incr(
            self.name,
            args=args,
            kwargs=kwargs,
        )

        # Call parent to execute async
        return super().apply_async(args=args, kwargs=kwargs, **options)


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
