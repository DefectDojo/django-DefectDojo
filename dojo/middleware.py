import logging
import re
import time
from contextlib import suppress
from threading import local
from urllib.parse import quote

import pghistory.middleware
import requests
from django.conf import settings
from django.contrib import messages
from django.db import models
from django.http import HttpResponseRedirect
from django.shortcuts import redirect
from django.urls import reverse
from social_core.exceptions import AuthCanceled, AuthFailed, AuthForbidden, AuthTokenError
from social_django.middleware import SocialAuthExceptionMiddleware
from watson.middleware import SearchContextMiddleware
from watson.search import search_context_manager

from dojo.models import Dojo_User
from dojo.product_announcements import LongRunningRequestProductAnnouncement

logger = logging.getLogger(__name__)

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


class CustomSocialAuthExceptionMiddleware(SocialAuthExceptionMiddleware):
    def process_exception(self, request, exception):
        if isinstance(exception, requests.exceptions.RequestException):
            messages.error(request, settings.SOCIAL_AUTH_EXCEPTION_MESSAGE_REQUEST_EXCEPTION)
            return redirect("/login?force_login_form")
        if isinstance(exception, AuthCanceled):
            messages.warning(request, settings.SOCIAL_AUTH_EXCEPTION_MESSAGE_AUTH_CANCELED)
            return redirect("/login?force_login_form")
        if isinstance(exception, AuthFailed):
            messages.error(request, settings.SOCIAL_AUTH_EXCEPTION_MESSAGE_AUTH_FAILED)
            return redirect("/login?force_login_form")
        if isinstance(exception, AuthForbidden):
            messages.error(request, settings.SOCIAL_AUTH_EXCEPTION_MESSAGE_AUTH_FORBIDDEN)
            return redirect("/login?force_login_form")
        if isinstance(exception, AuthTokenError):
            messages.error(request, settings.SOCIAL_AUTH_EXCEPTION_MESSAGE_AUTH_TOKEN_ERROR)
            return redirect("/login?force_login_form")
        if isinstance(exception, TypeError) and "'NoneType' object is not iterable" in str(exception):
            logger.warning("OIDC login error: NoneType is not iterable")
            messages.error(request, settings.SOCIAL_AUTH_EXCEPTION_MESSAGE_NONE_TYPE)
            return redirect("/login?force_login_form")
        logger.error(f"Unhandled exception during social login: {exception}")
        return super().process_exception(request, exception)


class DojoSytemSettingsMiddleware:
    _thread_local = local()

    def __init__(self, get_response):
        self.get_response = get_response
        from dojo.models import System_Settings  # noqa: PLC0415 circular import
        # Use classmethod directly to avoid keeping reference to middleware instance
        models.signals.post_save.connect(DojoSytemSettingsMiddleware.cleanup, sender=System_Settings)

    def __call__(self, request):
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
        from dojo.models import System_Settings  # noqa: PLC0415 circular import
        system_settings = System_Settings.objects.get(no_cache=True)
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
            # logger.debug('no cached value found, loading system settings from db')
            return self.get_from_db(*args, **kwargs)

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
        """Override watson's close behavior to trigger async updates when above threshold."""
        if search_context_manager.is_active():
            from django.conf import settings  # noqa: PLC0415 circular import

            # Extract tasks and check if we should trigger async update
            captured_tasks = self._extract_tasks_for_async()

            # Get total number of instances across all model types
            total_instances = sum(len(pk_list) for pk_list in captured_tasks.values())
            threshold = getattr(settings, "WATSON_ASYNC_INDEX_UPDATE_THRESHOLD", 100)

            # only needed when at least one model instance is updated
            if total_instances > 0:
                # If threshold is below 0, async updating is disabled
                if threshold < 0:
                    logger.debug(f"AsyncSearchContextMiddleware: Async updating disabled (threshold={threshold}), using synchronous update")
                elif total_instances > threshold:
                    logger.debug(f"AsyncSearchContextMiddleware: {total_instances} instances > {threshold} threshold, triggering async update")
                    self._trigger_async_index_update(captured_tasks)
                    # Invalidate to prevent synchronous index update by super()._close_search_context()
                    search_context_manager.invalidate()
                else:
                    logger.debug(f"AsyncSearchContextMiddleware: {total_instances} instances <= {threshold} threshold, using synchronous update")
                    # Let watson handle synchronous update for small numbers

        super()._close_search_context(request)

    def _extract_tasks_for_async(self):
        """Extract tasks from the search context and group by model type for async processing."""
        current_tasks, _is_invalid = search_context_manager._stack[-1]

        # Group by model type for efficient batch processing
        model_groups = {}
        for _engine, obj in current_tasks:
            model_key = f"{obj._meta.app_label}.{obj._meta.model_name}"
            if model_key not in model_groups:
                model_groups[model_key] = []
            model_groups[model_key].append(obj.pk)

        # Log what we extracted per model type
        for model_key, pk_list in model_groups.items():
            logger.debug(f"AsyncSearchContextMiddleware: Extracted {len(pk_list)} {model_key} instances for async indexing")

        return model_groups

    def _trigger_async_index_update(self, model_groups):
        """Trigger async tasks to update search indexes, chunking large lists into batches of settings.WATSON_ASYNC_INDEX_UPDATE_BATCH_SIZE."""
        if not model_groups:
            return

        # Import here to avoid circular import
        from django.conf import settings  # noqa: PLC0415 circular import

        from dojo.tasks import update_watson_search_index_for_model  # noqa: PLC0415 circular import

        # Create tasks per model type, chunking large lists into configurable batches
        for model_name, pk_list in model_groups.items():
            # Chunk into batches using configurable batch size (compatible with Python 3.11)
            batch_size = getattr(settings, "WATSON_ASYNC_INDEX_UPDATE_BATCH_SIZE", 1000)
            batches = [pk_list[i:i + batch_size] for i in range(0, len(pk_list), batch_size)]

            # Create tasks for each batch and log each one
            for i, batch in enumerate(batches, 1):
                logger.debug(f"AsyncSearchContextMiddleware: Triggering batch {i}/{len(batches)} for {model_name}: {len(batch)} instances")
                update_watson_search_index_for_model(model_name, batch)
