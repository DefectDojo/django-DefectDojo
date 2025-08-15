from functools import wraps

from django.shortcuts import redirect
from django.urls import reverse

from dojo.models import System_Settings


def v3_migration_enabled():
    """Returns whether v3 migration is enabled."""
    return System_Settings.objects.get().enable_v3_migration


def redirect_view(to: str):
    """"View" that redirects to the view named in 'to.'"""
    def _redirect(request, **kwargs):
        return redirect(to, **kwargs)
    return _redirect


def get_migration_urlconf():
    """Returns the urlconf to use, based on the v3 migration setting."""
    if v3_migration_enabled():
        return "dojo.v3_migration.urls"
    return "dojo.urls"


def v3_migration(**redirect_map: dict[str, str]):
    """
    Wrapper for views; redirect_map should map v2 urlpattern names to v3 urlpattern names. If v3 migrations are enabled,
    visiting the v2 url will redirect to the v3 url.
    """
    def _decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            if request.resolver_match.view_name in redirect_map.values() or not v3_migration_enabled():
                # No need to redirect; can just call the view.
                return view_func(request, **kwargs)
            # Need to redirect
            redirect_view_name = redirect_map.get(request.resolver_match.view_name)
            return redirect(reverse(redirect_view_name, args=args, kwargs=kwargs))
        return _wrapped
    return _decorator
