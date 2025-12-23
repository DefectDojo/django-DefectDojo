from unittest.mock import patch

from django.contrib import messages
from django.contrib.auth.models import AnonymousUser
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponse
from django.test import RequestFactory, override_settings
from requests.exceptions import ConnectionError as RequestsConnectionError
from social_core.exceptions import AuthCanceled, AuthFailed, AuthForbidden, AuthTokenError

from dojo.middleware import CustomSocialAuthExceptionMiddleware

from .dojo_test_case import DojoTestCase


class TestSocialAuthMiddlewareUnit(DojoTestCase):

    """
    Unit tests:
    Directly test CustomSocialAuthExceptionMiddleware behavior
    by simulating exceptions (ConnectionError, AuthCanceled, AuthFailed, AuthForbidden),
    without relying on actual backend configuration or whether the
    /complete/<backend>/ URLs are registered and accessible.
    """

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
            (RequestsConnectionError("Host unreachable"), "Please use the standard login below."),
            (AuthCanceled("User canceled login"), "Social login was canceled. Please try again or use the standard login."),
            (AuthFailed("Token exchange failed"), "Social login failed. Please try again or use the standard login."),
            (AuthForbidden("User not allowed"), "You are not authorized to log in via this method. Please contact support or use the standard login."),
            (AuthTokenError("Invalid or expired token"), "Social login failed due to an invalid or expired token. Please try again or use the standard login."),
        ]
        for path in login_paths:
            for exception, expected_message in exceptions:
                with self.subTest(path=path, exception=type(exception).__name__):
                    request = self._prepare_request(path)
                    response = self.middleware.process_exception(request, exception)
                    self.assertEqual(response.status_code, 302)
                    self.assertEqual(response.url, "/login?force_login_form")
                    storage = list(messages.get_messages(request))
                    self.assertTrue(any(expected_message in str(msg) for msg in storage))

    def test_non_social_auth_path_still_redirects_on_auth_exception(self):
        """Ensure middleware handles AuthFailed even on unrelated paths."""
        request = self._prepare_request("/some/other/path/")
        exception = AuthFailed("Should be handled globally")
        response = self.middleware.process_exception(request, exception)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/login?force_login_form")
        storage = list(messages.get_messages(request))
        self.assertTrue(any("Social login failed. Please try again or use the standard login." in str(msg) for msg in storage))

    def test_non_social_auth_path_redirects_on_auth_forbidden(self):
        """Ensure middleware handles AuthForbidden even on unrelated paths."""
        request = self._prepare_request("/some/other/path/")
        exception = AuthForbidden("User not allowed")
        response = self.middleware.process_exception(request, exception)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/login?force_login_form")
        storage = list(messages.get_messages(request))
        self.assertTrue(any("You are not authorized to log in via this method." in str(msg) for msg in storage))

    def test_type_error_none_type_iterable_redirect(self):
        """Ensure middleware catches 'NoneType' object is not iterable TypeError and redirects."""
        request = self._prepare_request("/login/oidc/")
        exception = TypeError("'NoneType' object is not iterable")
        response = self.middleware.process_exception(request, exception)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/login?force_login_form")
        storage = list(messages.get_messages(request))
        self.assertTrue(any("An unexpected error occurred during social login." in str(msg) for msg in storage))


@override_settings(
    AUTHENTICATION_BACKENDS=(
        "social_core.backends.github.GithubOAuth2",
        "social_core.backends.gitlab.GitLabOAuth2",
        "social_core.backends.keycloak.KeycloakOAuth2",
        "social_core.backends.azuread_tenant.AzureADTenantOAuth2",
        "social_core.backends.auth0.Auth0OAuth2",
        "social_core.backends.okta.OktaOAuth2",
        "social_core.backends.open_id_connect.OpenIdConnectAuth",
        "django.contrib.auth.backends.ModelBackend",
    ),
)
class TestSocialAuthIntegrationFailures(DojoTestCase):

    """
    Integration tests:
    Simulate social login failures by calling /complete/<backend>/ URLs
    and mocking auth_complete() to raise AuthFailed, AuthCanceled, and AuthForbidden.
    Verifies that the middleware is correctly integrated and handles backend failures.
    """

    BACKEND_CLASS_PATHS = {
        "github": "social_core.backends.github.GithubOAuth2",
        "gitlab": "social_core.backends.gitlab.GitLabOAuth2",
        "keycloak": "social_core.backends.keycloak.KeycloakOAuth2",
        "azuread-tenant-oauth2": "social_core.backends.azuread_tenant.AzureADTenantOAuth2",
        "auth0": "social_core.backends.auth0.Auth0OAuth2",
        "okta-oauth2": "social_core.backends.okta.OktaOAuth2",
        "oidc": "social_core.backends.open_id_connect.OpenIdConnectAuth",
    }

    def _test_backend_exception(self, backend_slug, exception, expected_message):
        backend_class_path = self.BACKEND_CLASS_PATHS[backend_slug]
        with patch(f"{backend_class_path}.auth_complete", side_effect=exception):
            response = self.client.get(f"/complete/{backend_slug}/", follow=True)
            self.assertEqual(response.status_code, 200)
            self.assertContains(response, expected_message)

    def test_all_backends_auth_failed(self):
        for backend in self.BACKEND_CLASS_PATHS:
            with self.subTest(backend=backend):
                self._test_backend_exception(backend, AuthFailed(backend=None), "Social login failed. Please try again or use the standard login.")

    def test_all_backends_auth_canceled(self):
        for backend in self.BACKEND_CLASS_PATHS:
            with self.subTest(backend=backend):
                self._test_backend_exception(backend, AuthCanceled(backend=None), "Social login was canceled. Please try again or use the standard login.")

    def test_all_backends_auth_forbidden(self):
        for backend in self.BACKEND_CLASS_PATHS:
            with self.subTest(backend=backend):
                self._test_backend_exception(
                    backend,
                    AuthForbidden(backend=None),
                    "You are not authorized to log in via this method. Please contact support or use the standard login.",
                )
