import logging
import os
from logging.config import dictConfig

from celery import Celery, Task
from celery.signals import setup_logging, task_postrun, task_prerun
from django.conf import settings
from django.db import close_old_connections

logger = logging.getLogger(__name__)

# set the default Django settings module for the 'celery' program.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dojo.settings.settings")


class DojoAsyncTask(Task):

    """
    Base task class that provides dojo_async_task functionality without using a decorator.

    This class:
    - Injects user context into task kwargs (on dispatch via apply_async)
    - Restores user context in the worker (on execution via __call__)
    - Tracks task calls for performance testing
    - Supports all Celery features (signatures, chords, groups, chains)
    """

    def __call__(self, *args, **kwargs):
        """
        Restore user context in the celery worker via crum.impersonate.

        The apply_async method injects ``async_user`` into kwargs when a task
        is dispatched. Here we pop it and set it as the current user in
        thread-local storage so that all downstream code — including nested
        dojo_dispatch_task calls — sees the correct user via
        get_current_user().

        When a task is called directly (not via apply_async), async_user is
        not in kwargs. In that case we leave the existing crum context
        intact so that callers who already set a user (e.g. via
        crum.impersonate in tests or request middleware) are not disrupted.
        """
        if "async_user" not in kwargs:
            return super().__call__(*args, **kwargs)

        import crum  # noqa: PLC0415

        user = kwargs.pop("async_user")
        with crum.impersonate(user):
            return super().__call__(*args, **kwargs)

    def apply_async(self, args=None, kwargs=None, **options):
        """Override apply_async to inject user context and track tasks."""
        from dojo.decorators import dojo_async_task_counter  # noqa: PLC0415 circular import
        from dojo.utils import get_current_user  # noqa: PLC0415 circular import

        if kwargs is None:
            kwargs = {}

        # Inject user context for Dojo tasks only. Celery built-in tasks (e.g.
        # celery.backend_cleanup) do not accept custom kwargs.
        task_name = self.name or ""
        if not task_name.startswith("celery.") and "async_user" not in kwargs:
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


class PluggableContextTask(DojoAsyncTask):

    """
    Extends DojoAsyncTask with pluggable context managers loaded from settings.

    CELERY_TASK_CONTEXT_MANAGERS is a list of dotted paths to callables that
    return context managers. Each task execution is wrapped in all of them.
    This replaces the celery signal-based approach (task_prerun/task_postrun)
    which does not work reliably with prefork worker pools.
    """

    def __call__(self, *args, **kwargs):
        from contextlib import ExitStack  # noqa: PLC0415

        from django.utils.module_loading import import_string  # noqa: PLC0415

        cm_paths = getattr(settings, "CELERY_TASK_CONTEXT_MANAGERS", [])
        if not cm_paths:
            return super().__call__(*args, **kwargs)

        # ExitStack ensures all entered context managers are properly exited
        # (via __exit__) even if the task raises an exception, so cleanup
        # and batch dispatch always happen.
        with ExitStack() as stack:
            for path in cm_paths:
                cm_factory = import_string(path)
                stack.enter_context(cm_factory())
            return super().__call__(*args, **kwargs)


class PgHistoryTask(PluggableContextTask):

    """
    Custom Celery base task that automatically applies pghistory context.

    This class inherits from PluggableContextTask to provide:
    - User context injection and task tracking (from DojoAsyncTask)
    - Pluggable context managers from settings (from PluggableContextTask)
    - Automatic pghistory context application (from this class)

    When a task is dispatched via dojo_dispatch_task or dojo_async_task, the current
    pghistory context is captured and passed in kwargs as "_pgh_context". This base
    class extracts that context and applies it before running the task, ensuring all
    database events share the same context as the original request.
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


@task_prerun.connect
def close_old_db_connections_before_task(task=None, **kwargs):
    if task is not None and getattr(task.request, "is_eager", False):
        return
    close_old_connections()


@task_postrun.connect
def close_old_db_connections_after_task(task=None, **kwargs):
    if task is not None and getattr(task.request, "is_eager", False):
        return
    close_old_connections()


# from celery import current_app

# _ = current_app.loader.import_default_modules()

# tasks = list(sorted(name for name in current_app.tasks
#                             if not name.startswith('celery.')))

# logger.debug('registered celery tasks:')
# for task in tasks:
#     logger.debug(task)
