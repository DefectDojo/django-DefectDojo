from django.http import HttpResponseRedirect
from django.conf import settings
from django.utils import timezone
from django.utils.http import urlquote
from dojo.utils import get_system_setting
import functools
from re import compile


EXEMPT_URLS = [compile(settings.LOGIN_URL.lstrip('/'))]
if hasattr(settings, 'LOGIN_EXEMPT_URLS'):
    EXEMPT_URLS += [compile(expr) for expr in settings.LOGIN_EXEMPT_URLS]


def patch_user(get_response):
    """Middleware patching request.user with some Dojo-specific functionality.

    This is necessary because Django doesn't allow using a proxy model as
    AUTH_USER_MODEL, which clearly would be the right way for doing these things.
    """

    def _patch_user(request):
        try:
            user = request.user
        except AttributeError:
            pass
        else:
            if user is not None:
                # Cache permission check results for the duration of the request
                user.has_perm = functools.lru_cache(maxsize=None)(user.has_perm)
        return get_response(request)

    return _patch_user


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
        response = self.get_response(request)

        assert hasattr(request, 'user'), "The Login Required middleware\
 requires authentication middleware to be installed. Edit your\
 MIDDLEWARE_CLASSES setting to insert\
 'django.contrib.auth.middleware.AuthenticationMiddleware'. If that doesn't\
 work, ensure your TEMPLATE_CONTEXT_PROCESSORS setting includes\
 'django.core.context_processors.auth'."
        if not request.user.is_authenticated:
            path = request.path_info.lstrip('/')
            if not any(m.match(path) for m in EXEMPT_URLS):
                if path == 'logout':
                    fullURL = "%s?next=%s" % (settings.LOGIN_URL, '/')
                else:
                    fullURL = "%s?next=%s" % (settings.LOGIN_URL, urlquote(request.get_full_path()))
                return HttpResponseRedirect(fullURL)
        return response


class TimezoneMiddleware:
    """
    Middleware that checks the configured timezone to use in each request
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        timezone.activate(get_system_setting('time_zone'))
        return response
