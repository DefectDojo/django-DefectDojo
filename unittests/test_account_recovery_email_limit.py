from django.core import mail
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse

from dojo.models import User

EMAIL = "recover@example.com"
PASSWORD = "Unused-Pass-1234!"


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    ACCOUNT_RECOVERY_EMAILS_PER_HOUR=2,
)
class AccountRecoveryEmailLimitTest(TestCase):

    """Password reset and forgot-username send a bounded number of emails per address per hour."""

    def setUp(self):
        cache.clear()
        User.objects.create_user(username="recover-user", password=PASSWORD, email=EMAIL)

    def tearDown(self):
        cache.clear()

    def _post(self, name, times):
        responses = [self.client.post(reverse(name), {"email": EMAIL}) for _ in range(times)]
        for response in responses:
            # The page answers the same way whether or not a message went out.
            self.assertEqual(302, response.status_code, response.content[:300])
        return responses

    def test_password_reset_emails_are_limited_per_address(self):
        self._post("password_reset", 4)
        self.assertEqual(2, len(mail.outbox))

    def test_forgot_username_emails_are_limited_per_address(self):
        self._post("forgot_username", 4)
        self.assertEqual(2, len(mail.outbox))

    def test_the_two_flows_are_counted_separately(self):
        self._post("password_reset", 2)
        self._post("forgot_username", 2)
        self.assertEqual(4, len(mail.outbox))

    @override_settings(ACCOUNT_RECOVERY_EMAILS_PER_HOUR=0)
    def test_zero_disables_the_limit(self):
        self._post("password_reset", 4)
        self.assertEqual(4, len(mail.outbox))
