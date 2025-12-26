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


class DojoAsyncTask(Task):

    """
    Base task class that provides dojo_async_task functionality without using a decorator.

    This class:
    - Injects user context into task kwargs
    - Tracks task calls for performance testing
    - Handles sync/async execution based on user settings
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

        # Track task call (only if not already tracked by __call__)
        # Check if this is a direct call to apply_async (not from __call__)
        # by checking if _dojo_tracked is not set
        if not getattr(self, "_dojo_tracked", False):
            dojo_async_task_counter.incr(
                self.name,
                args=args,
                kwargs=kwargs,
            )

        # Call parent to execute async
        return super().apply_async(args=args, kwargs=kwargs, **options)

    def s(self, *args, **kwargs):
        """Create a mutable signature with injected user context."""
        from dojo.decorators import dojo_async_task_counter  # noqa: PLC0415 circular import
        from dojo.utils import get_current_user  # noqa: PLC0415 circular import

        if "async_user" not in kwargs:
            kwargs["async_user"] = get_current_user()

        # Track task call
        dojo_async_task_counter.incr(
            self.name,
            args=args,
            kwargs=kwargs,
        )

        return super().s(*args, **kwargs)

    def si(self, *args, **kwargs):
        """Create an immutable signature with injected user context."""
        from dojo.decorators import dojo_async_task_counter  # noqa: PLC0415 circular import
        from dojo.utils import get_current_user  # noqa: PLC0415 circular import

        if "async_user" not in kwargs:
            kwargs["async_user"] = get_current_user()

        # Track task call
        dojo_async_task_counter.incr(
            self.name,
            args=args,
            kwargs=kwargs,
        )

        return super().si(*args, **kwargs)

    def __call__(self, *args, **kwargs):
        """
        Override __call__ to handle direct task calls with sync/async logic.

        This replicates the behavior of the dojo_async_task decorator wrapper.
        """
        # In Celery worker execution, __call__ is how tasks actually run.
        # We only want the sync/async decision when tasks are called directly
        # from application code (task(...)), not when the worker is executing a message.
        if not getattr(self.request, "called_directly", True):
            return super().__call__(*args, **kwargs)

        from dojo.decorators import dojo_async_task_counter, we_want_async  # noqa: PLC0415 circular import
        from dojo.utils import get_current_user  # noqa: PLC0415 circular import

        # Inject user context if not already present
        if "async_user" not in kwargs:
            kwargs["async_user"] = get_current_user()

        # Track task call
        dojo_async_task_counter.incr(
            self.name,
            args=args,
            kwargs=kwargs,
        )

        # Extract countdown if present (don't pass to sync execution)
        countdown = kwargs.pop("countdown", 0)

        # Check if we should run async or sync
        if we_want_async(*args, func=self, **kwargs):
            # Mark as tracked to avoid double tracking in apply_async
            self._dojo_tracked = True
            try:
                # Run asynchronously
                return self.apply_async(args=args, kwargs=kwargs, countdown=countdown)
            finally:
                # Clean up the flag
                delattr(self, "_dojo_tracked")
        else:
            # Run synchronously in-process, matching the original decorator behavior: func(*args, **kwargs)
            # Remove sync from kwargs as it's a control flag, not a task argument.
            kwargs.pop("sync", None)
            return self.run(*args, **kwargs)


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
