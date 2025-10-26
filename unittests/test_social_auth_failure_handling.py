
from django.contrib import messages
from django.contrib.auth.models import AnonymousUser
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponse
from django.test import RequestFactory
from requests.exceptions import ConnectionError as RequestsConnectionError
from social_core.exceptions import AuthCanceled, AuthFailed

from dojo.middleware import CustomSocialAuthExceptionMiddleware

from .dojo_test_case import DojoTestCase


class TestSocialAuthFailureHandling(DojoTestCase):

    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = CustomSocialAuthExceptionMiddleware(lambda *_: HttpResponse("OK"))

    def _prepare_request(self, path):
        request = self.factory.get(path)
        request.user = AnonymousUser()
        SessionMiddleware(lambda *_: None).process_request(request)
        request.session.save()
        request._messages = FallbackStorage(request)
        return request

    def test_social_auth_exception_redirects_to_login(self):
        login_paths = [
            "/login/oidc/",
            "/login/auth0/",
            "/login/google-oauth2/",
            "/login/okta-oauth2/",
            "/login/azuread-tenant-oauth2/",
            "/login/gitlab/",
            "/login/keycloak-oauth2/",
            "/login/github/",
        ]
        exceptions = [
            (RequestsConnectionError("Host unreachable"), "Login via social authentication is temporarily unavailable. Please use the standard login below."),
            (AuthCanceled("User canceled login"), "Social login was canceled. Please try again or use the standard login."),
            (AuthFailed("Token exchange failed"), "Social login failed. Please try again or use the standard login."),
        ]
        for path in login_paths:
            for exception, expected_message in exceptions:
                with self.subTest(path=path, exception=type(exception).__name__):
                    request = self._prepare_request(path)
                    response = self.middleware.process_exception(request, exception)
                    self.assertEqual(response.status_code, 302)
                    self.assertEqual(response.url, "/login")
                    storage = list(messages.get_messages(request))
                    self.assertTrue(any(expected_message in str(msg) for msg in storage))
