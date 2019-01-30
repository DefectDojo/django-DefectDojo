from django.http import HttpResponseRedirect
from django.conf import settings
from django.utils import timezone
from django.utils.http import urlquote
from dojo.utils import get_system_setting

from django.utils.deprecation import MiddlewareMixin

from re import compile


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
        # One-time configuration and initialization.

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.

        response = self.get_response(request)

        # Code to be executed for each request/response after
        # the view is called.

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
        # One-time configuration and initialization.

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.

        response = self.get_response(request)

        timezone.activate(get_system_setting('time_zone'))
        # Code to be executed for each request/response after
        # the view is called.

        return response

    # def process_request(self, request):
    #     timezone.activate(get_system_setting('time_zone'))


