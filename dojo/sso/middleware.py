import logging

import requests
from django.conf import settings
from django.contrib import messages
from django.shortcuts import redirect
from social_core.exceptions import AuthCanceled, AuthFailed, AuthForbidden, AuthTokenError
from social_django.middleware import SocialAuthExceptionMiddleware

logger = logging.getLogger(__name__)


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
