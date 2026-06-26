from types import SimpleNamespace

from django.conf import settings
from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase
from django.utils import translation

from dojo.middleware import LanguagePreferenceMiddleware, set_language_cookie

COOKIE = settings.LANGUAGE_COOKIE_NAME


def _user(language="", *, authenticated=True):
    return SimpleNamespace(
        is_authenticated=authenticated,
        usercontactinfo=SimpleNamespace(language=language),
    )


class TestSetLanguageCookie(SimpleTestCase):

    def test_sets_cookie_when_language_given(self):
        response = set_language_cookie(HttpResponse(), "pt-br")
        self.assertEqual(response.cookies[COOKIE].value, "pt-br")

    def test_clears_cookie_when_blank(self):
        # delete_cookie clears the value so LocaleMiddleware falls back to default.
        response = set_language_cookie(HttpResponse(), "")
        self.assertEqual(response.cookies[COOKIE].value, "")


class TestLanguagePreferenceMiddleware(SimpleTestCase):

    def setUp(self):
        self.factory = RequestFactory()
        self.addCleanup(translation.deactivate)

    def _run(self, request):
        captured = {}

        def get_response(req):
            captured["active"] = translation.get_language()
            return HttpResponse()

        response = LanguagePreferenceMiddleware(get_response)(request)
        return response, captured

    def test_seeds_and_activates_when_cookie_absent(self):
        request = self.factory.get("/dashboard")
        request.user = _user("pt-br")
        response, captured = self._run(request)
        self.assertEqual(request.LANGUAGE_CODE, "pt-br")
        self.assertEqual(captured["active"], "pt-br")
        self.assertEqual(response.cookies[COOKIE].value, "pt-br")

    def test_noop_when_cookie_present(self):
        request = self.factory.get("/dashboard")
        request.COOKIES[COOKIE] = "ru"
        request.user = _user("pt-br")
        response, _ = self._run(request)
        self.assertNotIn(COOKIE, response.cookies)
        self.assertFalse(hasattr(request, "LANGUAGE_CODE"))

    def test_skips_api_requests(self):
        request = self.factory.get("/api/v2/findings/")
        request.user = _user("pt-br")
        response, _ = self._run(request)
        self.assertNotIn(COOKIE, response.cookies)

    def test_skips_anonymous_users(self):
        request = self.factory.get("/dashboard")
        request.user = _user("pt-br", authenticated=False)
        response, _ = self._run(request)
        self.assertNotIn(COOKIE, response.cookies)

    def test_noop_when_no_stored_preference(self):
        request = self.factory.get("/dashboard")
        request.user = _user("")
        response, _ = self._run(request)
        self.assertNotIn(COOKIE, response.cookies)


class TestI18nConfiguration(SimpleTestCase):

    def test_locale_middleware_enabled(self):
        self.assertIn("django.middleware.locale.LocaleMiddleware", settings.MIDDLEWARE)

    def test_language_preference_middleware_runs_after_auth(self):
        mw = settings.MIDDLEWARE
        self.assertIn("dojo.middleware.LanguagePreferenceMiddleware", mw)
        self.assertGreater(
            mw.index("dojo.middleware.LanguagePreferenceMiddleware"),
            mw.index("django.contrib.auth.middleware.AuthenticationMiddleware"),
        )

    def test_only_audited_languages_are_offered(self):
        self.assertEqual({code for code, _name in settings.LANGUAGES}, {"en", "pt-br", "ru"})

    def test_locale_paths_point_at_dojo_locale(self):
        self.assertTrue(any(str(path).endswith("dojo/locale") for path in settings.LOCALE_PATHS))
