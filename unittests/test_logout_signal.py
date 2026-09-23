from unittest.mock import Mock

from django.contrib.auth.signals import user_logged_out
from django.test import RequestFactory

from dojo.utils import log_user_logout

from .dojo_test_case import DojoTestCase


class LogUserLogoutSignalTest(DojoTestCase):

    """
    Regression tests for the user_logged_out receiver in dojo.utils.

    An IdP-initiated SAML single-logout (POST /saml2/ls/) whose Django session has already
    expired reaches djangosaml2's do_logout_service, which calls django.contrib.auth.logout().
    When the request has no authenticated user, Django sends the user_logged_out signal with
    user=None. The receiver used to dereference user.username unconditionally and raised
    AttributeError: 'NoneType' object has no attribute 'username', turning the logout into a 500.
    """

    def _request(self):
        return RequestFactory().post("/saml2/ls/", REMOTE_ADDR="203.0.113.7")

    def test_receiver_does_not_crash_on_anonymous_logout(self):
        # Direct receiver call with user=None must not raise.
        try:
            log_user_logout(sender=None, request=self._request(), user=None)
        except AttributeError as exc:
            self.fail(f"log_user_logout raised on anonymous logout: {exc}")

    def test_logout_signal_with_none_user_does_not_raise(self):
        # End-to-end reproduction: firing the real signal with user=None (as auth.logout does
        # for an unauthenticated request) must not raise from our receiver.
        try:
            user_logged_out.send(sender=None, request=self._request(), user=None)
        except AttributeError as exc:
            self.fail(f"user_logged_out signal raised on anonymous logout: {exc}")

    def test_receiver_still_logs_username_for_authenticated_user(self):
        # The normal path is unchanged: a real user is still logged by username.
        user = Mock()
        user.username = "alice"
        with self.assertLogs("dojo.utils", level="INFO") as captured:
            log_user_logout(sender=None, request=self._request(), user=user)
        self.assertTrue(any("logout user: alice" in line for line in captured.output))
