import logging
import threading
from functools import wraps

from django.conf import settings
from django.http import Http404
from django_ratelimit import UNSAFE
from django_ratelimit.core import is_ratelimited
from django_ratelimit.exceptions import Ratelimited

from dojo.models import Dojo_User

logger = logging.getLogger(__name__)


class ThreadLocalTaskCounter:
    def __init__(self):
        self._thread_local = threading.local()

    def _get_task_list(self):
        if not hasattr(self._thread_local, "tasks"):
            self._thread_local.tasks = []
        return self._thread_local.tasks

    def _get_recording(self):
        return getattr(self._thread_local, "recording", False)

    def start(self):
        self._thread_local.recording = True
        self._get_task_list().clear()

    def stop(self):
        self._thread_local.recording = False

    def incr(self, task_name, model_id=None, args=None, kwargs=None):
        if not self._get_recording():
            return
        tasks = self._get_task_list()
        tasks.append({
            "task": task_name,
            "id": model_id,
            "args": args if args is not None else [],
            "kwargs": kwargs if kwargs is not None else {},
        })

    def get(self):
        return len(self._get_task_list())

    def get_tasks(self):
        return list(self._get_task_list())


# Create a shared instance
dojo_async_task_counter = ThreadLocalTaskCounter()


def we_want_async(*args, func=None, **kwargs):
    from dojo.utils import get_current_user  # noqa: PLC0415 circular import

    sync = kwargs.get("sync", False)
    if sync:
        logger.debug("dojo_async_task %s: running task in the foreground as sync=True has been found as kwarg", func)
        return False

    user = get_current_user()
    logger.debug("async user: %s", user)

    if not user:
        logger.debug("dojo_async_task %s: no current user, running task in the background", func)
        return True

    if Dojo_User.wants_block_execution(user):
        logger.debug("dojo_async_task %s: running task in the foreground as block_execution is set to True for %s", func, user)
        return False

    logger.debug("dojo_async_task %s: running task in the background as user has not set block_execution to True for %s", func, user)
    return True


# Defect Dojo performs all tasks asynchrnonously using celery
# *unless* the user initiating the task has set block_execution to True in their usercontactinfo profile
def dojo_async_task(func=None, *, signature=False):
    def decorator(func):
        @wraps(func)
        def __wrapper__(*args, **kwargs):
            from dojo.pghistory_utils import get_serializable_pghistory_context  # noqa: PLC0415 circular import
            from dojo.utils import get_current_user  # noqa: PLC0415 circular import

            user = get_current_user()
            kwargs["async_user"] = user

            # Capture pghistory context to pass to Celery worker
            # The PgHistoryTask base class will apply this context in the worker
            if pgh_context := get_serializable_pghistory_context():
                kwargs["_pgh_context"] = pgh_context

            dojo_async_task_counter.incr(
                func.__name__,
                args=args,
                kwargs=kwargs,
            )

            if signature:
                return func.si(*args, **kwargs)

            countdown = kwargs.pop("countdown", 0)
            if we_want_async(*args, func=func, **kwargs):
                # Return a signature for use in chord/group if requested
                # Execute the task
                return func.apply_async(args=args, kwargs=kwargs, countdown=countdown)
            return func(*args, **kwargs)
        return __wrapper__

    if func is None:
        return decorator
    return decorator(func)


def get_parameter_froms_args_kwargs(args, kwargs, parameter):
    model_or_id = None
    if isinstance(parameter, int):
        # Lookup value came as a positional argument
        args = list(args)
        if parameter >= len(args):
            raise ValueError("parameter index invalid: " + str(parameter))
        model_or_id = args[parameter]
    else:
        # Lookup value was passed as keyword argument
        model_or_id = kwargs.get(parameter, None)

    logger.debug("model_or_id: %s", model_or_id)

    if not model_or_id:
        logger.error("unable to get parameter: " + parameter)

    return model_or_id


def dojo_ratelimit(key="ip", rate=None, method=UNSAFE, *, block=False):
    def decorator(fn):
        @wraps(fn)
        def _wrapped(request, *args, **kw):
            limiter_block = getattr(settings, "RATE_LIMITER_BLOCK", block)
            limiter_rate = getattr(settings, "RATE_LIMITER_RATE", rate)
            limiter_lockout = getattr(settings, "RATE_LIMITER_ACCOUNT_LOCKOUT", False)
            old_limited = getattr(request, "limited", False)
            ratelimited = is_ratelimited(request=request, fn=fn,
                                         key=key, rate=limiter_rate, method=method,
                                         increment=True)
            request.limited = ratelimited or old_limited
            if ratelimited and limiter_block:
                if limiter_lockout:
                    username = request.POST.get("username", None)
                    if username:
                        dojo_user = Dojo_User.objects.filter(username=username).first()
                        if dojo_user:
                            dojo_user.enable_force_password_reset()
                raise Ratelimited
            return fn(request, *args, **kw)
        return _wrapped

    return decorator


def require_v3_feature_set():
    """Decorator that raises 404 if the V3_FEATURE_LOCATIONS is False."""

    def decorator(func):
        @wraps(func)
        def _wrapped_view(request, *args, **kwargs):
            if not getattr(settings, "V3_FEATURE_LOCATIONS", False):
                msg = "V3_FEATURE_LOCATIONS must be enabled."
                raise Http404(msg)
            return func(request, *args, **kwargs)

        return _wrapped_view

    return decorator
