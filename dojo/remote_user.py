import logging
from django.contrib.auth.middleware import RemoteUserMiddleware as OriginalRemoteUserMiddleware
from django.contrib.auth.backends import RemoteUserBackend as OriginalRemoteUserBackend
from drf_spectacular.extensions import OpenApiAuthenticationExtension
from rest_framework.authentication import RemoteUserAuthentication as OriginalRemoteUserAuthentication
from netaddr import IPAddress
from dojo.settings import settings
from dojo.pipeline import assign_user_to_groups, cleanup_old_groups_for_user

logger = logging.getLogger(__name__)


class RemoteUserAuthentication(OriginalRemoteUserAuthentication):
    def authenticate(self, request):
        # process only if request is comming from the trusted proxy node
        if IPAddress(request.META['REMOTE_ADDR']) in settings.AUTH_REMOTEUSER_TRUSTED_PROXY:
            self.header = settings.AUTH_REMOTEUSER_USERNAME_HEADER
            if self.header in request.META:
                return super().authenticate(request)
            else:
                return None
        else:
            logger.debug('Requested came from untrusted proxy %s; This is list of trusted proxies: %s',
                IPAddress(request.META['REMOTE_ADDR']),
                settings.AUTH_REMOTEUSER_TRUSTED_PROXY)
            return None


class RemoteUserMiddleware(OriginalRemoteUserMiddleware):
    def process_request(self, request):
        # process only if request is comming from the trusted proxy node
        if IPAddress(request.META['REMOTE_ADDR']) in settings.AUTH_REMOTEUSER_TRUSTED_PROXY:
            self.header = settings.AUTH_REMOTEUSER_USERNAME_HEADER
            if self.header in request.META:
                return super().process_request(request)
            else:
                return
        else:
            logger.debug('Requested came from untrusted proxy %s; This is list of trusted proxies: %s',
                IPAddress(request.META['REMOTE_ADDR']),
                settings.AUTH_REMOTEUSER_TRUSTED_PROXY)
            return


class PersistentRemoteUserMiddleware(RemoteUserMiddleware):
    # same as https://github.com/django/django/blob/6654289f5b350dfca3dc4f6abab777459b906756/django/contrib/auth/middleware.py#L128
    force_logout_if_no_header = False


class RemoteUserBackend(OriginalRemoteUserBackend):
    # This part can be removed during the upgrade to Django 4.1 or higher. Older
    # versions (e.g. 3.2) is calling `configure_user` only for new users. In 4.1
    # this behavior is changed: `configure_user` is call every time.
    # https://github.com/django/django/pull/15492
    def authenticate(self, request, remote_user):
        user = super().authenticate(request, remote_user)
        return self.configure_user(request, user)

    def configure_user(self, request, user, created=True):
        changed = False

        if settings.AUTH_REMOTEUSER_EMAIL_HEADER and \
          settings.AUTH_REMOTEUSER_EMAIL_HEADER in request.META and \
          user.email != request.META[settings.AUTH_REMOTEUSER_EMAIL_HEADER]:
            user.email = request.META[settings.AUTH_REMOTEUSER_EMAIL_HEADER]
            logger.debug("Updating email for user %s to value %s", user.username, user.email)
            changed = True

        if settings.AUTH_REMOTEUSER_FIRSTNAME_HEADER and \
          settings.AUTH_REMOTEUSER_FIRSTNAME_HEADER in request.META and \
          user.first_name != request.META[settings.AUTH_REMOTEUSER_FIRSTNAME_HEADER]:
            user.first_name = request.META[settings.AUTH_REMOTEUSER_FIRSTNAME_HEADER]
            logger.debug("Updating first_name for user %s to value %s", user.username, user.first_name)
            changed = True

        if settings.AUTH_REMOTEUSER_LASTNAME_HEADER and \
          settings.AUTH_REMOTEUSER_LASTNAME_HEADER in request.META and \
          user.last_name != request.META[settings.AUTH_REMOTEUSER_LASTNAME_HEADER]:
            user.last_name = request.META[settings.AUTH_REMOTEUSER_LASTNAME_HEADER]
            logger.debug("Updating last_name for user %s to value %s", user.username, user.last_name)
            changed = True

        if settings.AUTH_REMOTEUSER_GROUPS_HEADER and \
          settings.AUTH_REMOTEUSER_GROUPS_HEADER in request.META:
            assign_user_to_groups(user, request.META[settings.AUTH_REMOTEUSER_GROUPS_HEADER].split(','), 'Remote')

        if settings.AUTH_REMOTEUSER_GROUPS_CLEANUP and \
          settings.AUTH_REMOTEUSER_GROUPS_HEADER and \
          settings.AUTH_REMOTEUSER_GROUPS_HEADER in request.META:
            cleanup_old_groups_for_user(user, request.META[settings.AUTH_REMOTEUSER_GROUPS_HEADER].split(','))

        if changed:
            user.save()

        return user


class RemoteUserScheme(OpenApiAuthenticationExtension):
    target_class = 'dojo.remote_user.RemoteUserAuthentication'
    name = 'remoteUserAuth'
    match_subclasses = True
    priority = 1

    def get_security_definition(self, auto_schema):
        return settings.SWAGGER_SETTINGS['SECURITY_DEFINITIONS']['remoteUserAuth']
