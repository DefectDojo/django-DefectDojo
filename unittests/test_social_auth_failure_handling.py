
from django.contrib.auth.models import AnonymousUser
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponse
from django.test import RequestFactory, override_settings
from requests.exceptions import ConnectionError as RequestsConnectionError

from dojo.middleware import CustomSocialAuthExceptionMiddleware

from .dojo_test_case import DojoTestCase


@override_settings(
    SOCIAL_AUTH_OIDC_AUTH_ENABLED=True,
    SOCIAL_AUTH_AUTH0_OAUTH2_ENABLED=True,
    GOOGLE_OAUTH_ENABLED=True,
    SOCIAL_AUTH_OKTA_OAUTH2_ENABLED=True,
    AZUREAD_TENANT_OAUTH2_ENABLED=True,
    GITLAB_OAUTH2_ENABLED=True,
    KEYCLOAK_OAUTH2_ENABLED=True,
    GITHUB_ENTERPRISE_OAUTH2_ENABLED=True,
)
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

        for path in login_paths:
            with self.subTest(path=path):
                request = self._prepare_request(path)
                response = self.middleware.process_exception(request, RequestsConnectionError("Host unreachable"))
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.url, "/login")
