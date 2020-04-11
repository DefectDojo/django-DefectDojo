from django.http import HttpResponseRedirect
from django.conf import settings
from django.utils.http import urlquote
from re import compile
from dojo.models import System_Settings


EXEMPT_URLS = [compile(settings.LOGIN_URL.lstrip('/'))]
if hasattr(settings, 'LOGIN_EXEMPT_URLS'):
    EXEMPT_URLS += [compile(expr) for expr in settings.LOGIN_EXEMPT_URLS]


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

        response = self.get_response(request)
        return response


def dojo_system_settings_middleware(get_response):
    """
    Middleware that caches a System_Settings model instance per request. There's lots of (legacy) code makin multiple
    database queries to get system settings from the database. This can result in over 50 database queries when
    rendering a view. This middleware reduces this to exactly one query. We may at some point want to refactor the
    System_Settings mechanism, but for now it's easier to just cache it (without requiring additional software such as Redis).
    """

    def middleware(request):

        System_Settings.objects.load()
        response = get_response(request)
        System_Settings.objects.cleanup()

        return response

    return middleware
