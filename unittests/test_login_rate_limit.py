import hashlib

from django.core.cache import cache
from django.test import RequestFactory, override_settings
from django.urls import reverse

from dojo.models import Dojo_User, UserContactInfo
from dojo.user.ui.views import login_password_ratelimit_key
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


@versioned_fixtures
@override_settings(RATE_LIMITER_BLOCK=True, RATE_LIMITER_ACCOUNT_LOCKOUT=True, RATE_LIMITER_RATE="2/m")
class LoginRateLimitTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        cache.clear()

    def tearDown(self):
        cache.clear()

    def _make_user(self, username, *, usable_password):
        user = Dojo_User.objects.create(username=username)
        if usable_password:
            user.set_password("correct-horse-battery-staple")
        else:
            user.set_unusable_password()
        user.save()
        UserContactInfo.objects.get_or_create(user=user)
        return user

    def _fail_logins(self, username, attempts=4):
        for i in range(attempts):
            self.client.post(reverse("login"), {"username": username, "password": f"wrong-{i}"})

    def test_lockout_forces_password_reset(self):
        user = self._make_user("ratelimit-password-user", usable_password=True)
        self._fail_logins(user.username)
        user.usercontactinfo.refresh_from_db()
        self.assertTrue(user.usercontactinfo.force_password_reset)

    def test_lockout_skips_account_without_usable_password(self):
        user = self._make_user("ratelimit-passwordless-user", usable_password=False)
        self._fail_logins(user.username)
        user.usercontactinfo.refresh_from_db()
        self.assertFalse(user.usercontactinfo.force_password_reset)

    def test_password_key_is_keyed(self):
        request = RequestFactory().post(reverse("login"), {"username": "x", "password": "hunter2"})
        key = login_password_ratelimit_key("group", request)
        self.assertNotIn("hunter2", key)
        self.assertNotEqual(hashlib.sha256(b"hunter2").hexdigest(), key)
        self.assertEqual(key, login_password_ratelimit_key("group", request))
        other = RequestFactory().post(reverse("login"), {"username": "x", "password": "hunter3"})
        self.assertNotEqual(key, login_password_ratelimit_key("group", other))
