import logging
import re
import time
from contextlib import suppress
from threading import local
from urllib.parse import quote

import pghistory.middleware
from django.conf import settings
from django.db import models
from django.dispatch import receiver
from django.http import HttpResponseRedirect
from django.urls import reverse
from watson.middleware import SearchContextMiddleware
from watson.search import search_context_manager

from dojo.caching import (
    cache_dict_to_model,
    dojo_settings_cache,
    invalidate_dojo_settings_cache,
    model_to_cache_dict,
    reset_l1_cache,
)
from dojo.models import Dojo_User
from dojo.product_announcements import LongRunningRequestProductAnnouncement

logger = logging.getLogger(__name__)

# Two-tier (in-process L1 + django.core.cache L2) read-through cache for the
# System_Settings singleton, via the shared dojo_settings_cache decorator. Stored
# as a plain dict (no pickled model graph) and rebuilt into a read-only instance
# per call. Write paths use ``objects.get(no_cache=True)`` and are unaffected.
SYSTEM_SETTINGS_CACHE_KEY = "dojo.system_settings.singleton"


@dojo_settings_cache(key=SYSTEM_SETTINGS_CACHE_KEY)
def _cached_system_settings_dict():
    from dojo.models import System_Settings  # noqa: PLC0415 circular import
    settings_obj = System_Settings.objects.get_from_db()
    # ``get_from_db`` returns an unsaved defaults instance (pk None) when the row
    # can't be read; returning None keeps that out of the cache so the next call
    # retries the DB instead of serving stale defaults.
    if settings_obj.pk is None:
        return None
    return model_to_cache_dict(settings_obj)


def get_cached_system_settings():
    from dojo.models import System_Settings  # noqa: PLC0415 circular import
    data = _cached_system_settings_dict()
    if not isinstance(data, dict):
        return System_Settings()
    return cache_dict_to_model(System_Settings, data)


@receiver(models.signals.post_save, sender="dojo.System_Settings")
def _invalidate_system_settings_cache(*args, **kwargs):
    # Connected at import time (string sender avoids the circular import) so the
    # bust fires in requests, Celery, commands and tests -- not only when a
    # middleware instance is constructed.
    invalidate_dojo_settings_cache(SYSTEM_SETTINGS_CACHE_KEY)


EXEMPT_URLS = [re.compile(settings.LOGIN_URL.lstrip("/"))]
if hasattr(settings, "LOGIN_EXEMPT_URLS"):
    EXEMPT_URLS += [re.compile(expr) for expr in settings.LOGIN_EXEMPT_URLS]


class LoginRequiredMiddleware:

    """
    Middleware that requires a user to be authenticated to view any page other
    than LOGIN_URL. Exemptions to this requirement can optionally be specified
    in settings via a list of regular expressions in LOGIN_EXEMPT_URLS (which
    you can copy from your urls.py).

    Requires authentication middleware and template context processors to be
    loaded. You'll get an error if they aren't.
    """

    def __init__(self, get_response):

        self.get_response = get_response

    def __call__(self, request):
        if not hasattr(request, "user"):
            msg = (
                "The Login Required middleware "
                "requires authentication middleware to be installed. Edit your "
                "MIDDLEWARE_CLASSES setting to insert "
                "'django.contrib.auth.middleware.AuthenticationMiddleware'. If that doesn't "
                "work, ensure your TEMPLATE_CONTEXT_PROCESSORS setting includes "
                "'django.core.context_processors.auth'."
            )
            raise AttributeError(msg)
        if not request.user.is_authenticated:
            path = request.path_info.lstrip("/")
            if not any(m.match(path) for m in EXEMPT_URLS):
                if path == "logout":
                    fullURL = f"{settings.LOGIN_URL}?next=/"
                else:
                    fullURL = f"{settings.LOGIN_URL}?next={quote(request.get_full_path())}"
                return HttpResponseRedirect(fullURL)

        if request.user.is_authenticated:
            path = request.path_info.lstrip("/")
            if Dojo_User.force_password_reset(request.user) and path != "change_password":
                return HttpResponseRedirect(reverse("change_password"))

        response = self.get_response(request)
        if request.user.is_authenticated:
            logger.debug("Authenticated user: %s", request.user)
            with suppress(ModuleNotFoundError):  # to avoid unittests to fail
                uwsgi = __import__("uwsgi", globals(), locals(), ["set_logvar"], 0)
                # this populates dd_user log var, so can appear in the uwsgi logs
                uwsgi.set_logvar("dd_user", str(request.user))
        return response


class DojoSytemSettingsMiddleware:
    _thread_local = local()

    def __init__(self, get_response):
        self.get_response = get_response
        from dojo.models import System_Settings  # noqa: PLC0415 circular import
        # Use classmethod directly to avoid keeping reference to middleware instance
        models.signals.post_save.connect(DojoSytemSettingsMiddleware.cleanup, sender=System_Settings)

    def __call__(self, request):
        # uwsgi/gunicorn reuse threads across requests, so the in-process L1 cache
        # (threading.local) would otherwise persist between requests. Reset it at
        # the start of each request so cached singletons are request-scoped.
        reset_l1_cache()
        self.load()
        try:
            # Store error in request for context processor to display
            # (We can't use messages here because MessageMiddleware runs after this middleware)
            if hasattr(self._thread_local, "system_settings_error"):
                request.system_settings_error = self._thread_local.system_settings_error
                # Clear from thread-local after copying to request
                delattr(self._thread_local, "system_settings_error")
            return self.get_response(request)
        finally:
            # ensure cleanup happens even if an exception occurs
            self.cleanup()

    def process_exception(self, request, exception):
        self.cleanup()

    @classmethod
    def get_system_settings(cls):
        if hasattr(cls._thread_local, "system_settings"):
            return cls._thread_local.system_settings
        return None

    @classmethod
    def cleanup(cls, *args, **kwargs):  # noqa: ARG003
        if hasattr(cls._thread_local, "system_settings"):
            del cls._thread_local.system_settings
        if hasattr(cls._thread_local, "system_settings_error"):
            delattr(cls._thread_local, "system_settings_error")

    @classmethod
    def load(cls):
        # cleanup any existing settings first to ensure fresh state
        cls.cleanup()
        # Read through the shared L1/L2 cache so requests don't each hit the DB
        # for the singleton. Freshness is bounded by the L1 TTL and busted on save.
        system_settings = get_cached_system_settings()
        cls._thread_local.system_settings = system_settings
        return system_settings


class System_Settings_Manager(models.Manager):

    def get_from_db(self, *args, **kwargs):
        # logger.debug('refreshing system_settings from db')
        from dojo.models import System_Settings  # noqa: PLC0415 circular import
        try:
            from_db = super().get(*args, **kwargs)
        except Exception as e:
            # Store error message in thread-local for middleware to display
            error_msg = str(e)
            if hasattr(DojoSytemSettingsMiddleware._thread_local, "system_settings_error"):
                # Only store the first error to avoid duplicates
                pass
            else:
                DojoSytemSettingsMiddleware._thread_local.system_settings_error = error_msg
            # Return defaults so app can still start - error will be displayed as warning message
            # logger.debug('unable to get system_settings from database, returning defaults. Exception was:', exc_info=True)
            return System_Settings()
        return from_db

    def get(self, no_cache=False, *args, **kwargs):  # noqa: FBT002 - this is bit hard to fix nice have this universally fixed
        if no_cache:
            # logger.debug('no_cache specified or cached value found, loading system settings from db')
            return self.get_from_db(*args, **kwargs)

        from_cache = DojoSytemSettingsMiddleware.get_system_settings()

        if not from_cache:
            # No per-request thread-local (e.g. outside a request / in Celery):
            # fall back to the shared L1/L2 cache.
            return get_cached_system_settings()

        return from_cache


class APITrailingSlashMiddleware:

    """
    Middleware that will send a more informative error response to POST requests
    made without the trailing slash. When this middleware is not active, POST requests
    without the trailing slash will return a 301 status code, with no explanation as to why
    """

    def __init__(self, get_response):

        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        path = request.path_info.lstrip("/")
        if request.method == "POST" and "api/v2/" in path and path[-1] != "/" and response.status_code == 400:
            response.data = {"message": "Please add a trailing slash to your request."}
            # you need to change private attribute `_is_render`
            # to call render second time
            response._is_rendered = False
            response.render()
        return response


class AdditionalHeaderMiddleware:

    """Middleware that will add an arbitray amount of HTTP Request headers toall requests."""

    def __init__(self, get_response):

        self.get_response = get_response

    def __call__(self, request):
        request.META.update(settings.ADDITIONAL_HEADERS)
        return self.get_response(request)


class PgHistoryMiddleware(pghistory.middleware.HistoryMiddleware):

    """
    Custom pghistory middleware for DefectDojo that extends the built-in HistoryMiddleware
    to add remote_addr context following the pattern from:
    https://django-pghistory.readthedocs.io/en/3.8.1/context/#middleware
    """

    def get_context(self, request):
        context = super().get_context(request)

        # Add remote address with proxy support
        remote_addr = request.META.get("HTTP_X_FORWARDED_FOR")
        # Get the first IP if there are multiple (proxy chain), or fall back to REMOTE_ADDR
        remote_addr = remote_addr.split(",")[0].strip() if remote_addr else request.META.get("REMOTE_ADDR")

        context["remote_addr"] = remote_addr
        return context


class LongRunningRequestAlertMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.ignored_paths = [
            re.compile(r"^/api/v2/.*"),
            re.compile(r"^/product/(?P<product_id>\d+)/import_scan_results$"),
            re.compile(r"^/engagement/(?P<engagement_id>\d+)/import_scan_results$"),
            re.compile(r"^/test/(?P<test_id>\d+)/re_import_scan_results"),
            re.compile(r"^/alerts/count"),
        ]

    def __call__(self, request):
        start_time = time.perf_counter()
        response = self.get_response(request)
        duration = time.perf_counter() - start_time
        if not any(pattern.match(request.path_info) for pattern in self.ignored_paths):
            LongRunningRequestProductAnnouncement(request=request, duration=duration)

        return response


class AsyncSearchContextMiddleware(SearchContextMiddleware):

    """
    Ensures Watson index updates are triggered asynchronously.
    Inherits from watson's SearchContextMiddleware to minimize the amount of code we need to maintain.
    """

    def _close_search_context(self, request):
        """Override watson's close behavior to always dispatch index updates asynchronously."""
        if search_context_manager.is_active():
            objects, _is_invalid = search_context_manager._stack[-1]
            _drain_search_context_to_async(objects, source="AsyncSearchContextMiddleware")

        # The set is now empty (or was already empty); watson's `end()` will
        # bulk-save an empty iterator and short-circuit. No need to invalidate.
        super()._close_search_context(request)


def _drain_search_context_to_async(objects, source):
    """
    Group `objects` ({(engine, obj), ...}) by model, dispatch one
    force_async celery task per WATSON_ASYNC_INDEX_UPDATE_BATCH_SIZE-sized
    batch, and `set.discard()` the drained entries from `objects` in place.

    `objects` is the `set` inside `search_context_manager._stack[-1][0]`.
    Mutating it in place is safe because watson's `_stack` is `threading.local`
    and callers (request close + the wrapped `add_to_context`) hold the
    active reference.
    """
    if not objects:
        return

    from dojo.celery_dispatch import dojo_dispatch_task  # noqa: PLC0415 circular import
    from dojo.tasks import update_watson_search_index_for_model  # noqa: PLC0415 circular import

    # Snapshot before grouping so we don't iterate while mutating.
    snapshot = list(objects)
    model_groups = {}
    for _engine, obj in snapshot:
        model_key = f"{obj._meta.app_label}.{obj._meta.model_name}"
        model_groups.setdefault(model_key, []).append(obj.pk)

    batch_size = getattr(settings, "WATSON_ASYNC_INDEX_UPDATE_BATCH_SIZE", 1000)
    for model_name, pk_list in model_groups.items():
        batches = [pk_list[i:i + batch_size] for i in range(0, len(pk_list), batch_size)]
        # force_async=True keeps indexing off the request path even for users
        # with block_execution=True — index updates are slow and
        # never need to be synchronous from the user's perspective.
        for i, batch in enumerate(batches, 1):
            logger.debug(f"{source}: Triggering batch {i}/{len(batches)} for {model_name}: {len(batch)} instances")
            dojo_dispatch_task(update_watson_search_index_for_model, model_name, batch, force_async=True)

    for entry in snapshot:
        objects.discard(entry)


def install_intermediate_flush_hook():
    """
    Wrap `watson.search.search_context_manager.add_to_context` with a
    size-based flush. Once the per-request set reaches
    `WATSON_ASYNC_INDEX_UPDATE_BATCH_SIZE`, drain it into async tasks
    and clear it in place. Bounds memory on long-running requests
    (large imports) and starts celery batches earlier instead of
    dispatching all at end-of-request.

    Idempotent — safe to call multiple times.
    Setting WATSON_ASYNC_INDEX_UPDATE_BATCH_SIZE to 0 or below disables
    the hook at runtime.
    """
    cls = search_context_manager.__class__
    if getattr(cls, "_dd_intermediate_flush_installed", False):
        return

    original_add = cls.add_to_context

    def add_to_context_with_flush(self, engine, obj):
        original_add(self, engine, obj)
        threshold = getattr(settings, "WATSON_ASYNC_INDEX_UPDATE_BATCH_SIZE", 1000)
        if threshold <= 0 or not self._stack:
            return
        objects, is_invalid = self._stack[-1]
        if is_invalid or len(objects) < threshold:
            return
        _drain_search_context_to_async(objects, source="AsyncSearchContextMiddleware[intermediate]")

    cls.add_to_context = add_to_context_with_flush
    cls._dd_intermediate_flush_installed = True
    logger.debug("AsyncSearchContextMiddleware: intermediate flush hook installed on %s", cls.__name__)
