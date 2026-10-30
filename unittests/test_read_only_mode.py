import json

from django.contrib.messages import get_messages
from django.http import HttpResponse
from django.test import RequestFactory, override_settings
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.celery import app
from dojo.context_processors import globalize_vars
from dojo.middleware import READ_ONLY_MODE_MESSAGE, ReadOnlyModeMiddleware, get_cached_system_settings
from dojo.models import Product_Type, System_Settings, User
from dojo.system_settings.ui.forms import SystemSettingsForm

from .dojo_test_case import DojoTestCase, versioned_fixtures


def set_read_only_mode(*, enabled: bool) -> None:
    system_settings = System_Settings.objects.get(no_cache=True)
    system_settings.read_only_mode = enabled
    system_settings.save()


def admin_api_client() -> APIClient:
    token, _ = Token.objects.get_or_create(user=User.objects.get(username="admin"))
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
    return client


@versioned_fixtures
class TestReadOnlyModeSetting(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def test_read_only_mode_defaults_off(self):
        self.assertFalse(System_Settings.objects.get(no_cache=True).read_only_mode)

    def test_form_shows_read_only_mode(self):
        self.assertIn("read_only_mode", SystemSettingsForm().fields)


def rf_middleware(path, **headers):
    request = RequestFactory().post(path, **headers)
    return ReadOnlyModeMiddleware(lambda _request: HttpResponse("OK"))(request)


@versioned_fixtures
class TestReadOnlyModeMiddleware(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.api = admin_api_client()
        self.client.force_login(User.objects.get(username="admin"))

    def create_product_type(self, name):
        return self.api.post("/api/v2/product_types/", {"name": name}, format="json")

    def test_api_write_rejected_with_423(self):
        set_read_only_mode(enabled=True)
        response = self.create_product_type("Blocked")
        self.assertEqual(423, response.status_code)
        self.assertEqual(str(READ_ONLY_MODE_MESSAGE), response.json()["detail"])
        self.assertFalse(Product_Type.objects.filter(name="Blocked").exists())

    def test_api_write_allowed_when_off(self):
        set_read_only_mode(enabled=False)
        self.assertEqual(201, self.create_product_type("Allowed").status_code)

    def test_safe_methods_pass_when_locked(self):
        set_read_only_mode(enabled=True)
        for method in ("get", "head", "options"):
            with self.subTest(method=method):
                self.assertEqual(200, getattr(self.api, method)("/api/v2/product_types/").status_code)

    def test_page_post_redirects_back_with_message(self):
        set_read_only_mode(enabled=True)
        referer = "http://testserver" + reverse("product_type")
        response = self.client.post(reverse("add_product_type"), {"name": "Blocked"}, HTTP_REFERER=referer)
        self.assertEqual(302, response.status_code)
        self.assertEqual(referer, response["Location"])
        self.assertIn(str(READ_ONLY_MODE_MESSAGE), [str(m) for m in get_messages(response.wsgi_request)])
        self.assertFalse(Product_Type.objects.filter(name="Blocked").exists())
        # The API-key page starts with "api/" but is a page, not an API route.
        response = self.client.post("/api/key-v2", {}, HTTP_REFERER=referer)
        self.assertEqual(referer, response["Location"])

    def test_foreign_referer_falls_back_to_home(self):
        set_read_only_mode(enabled=True)
        response = self.client.post(reverse("add_product_type"), {"name": "Blocked"}, HTTP_REFERER="https://evil.example/x")
        self.assertEqual(reverse("home"), response["Location"])

    def test_machine_clients_get_423(self):
        set_read_only_mode(enabled=True)
        cases = [
            ("/api/v3/organizations/", {}),
            ("/finding/1/edit", {"HTTP_HX_REQUEST": "true"}),
            ("/finding/1/edit", {"HTTP_X_REQUESTED_WITH": "XMLHttpRequest"}),
        ]
        for path, headers in cases:
            with self.subTest(path=path, headers=headers):
                response = rf_middleware(path, **headers)
                self.assertEqual(423, response.status_code)
                self.assertEqual(str(READ_ONLY_MODE_MESSAGE), json.loads(response.content)["detail"])

    def test_exempt_paths_pass_when_locked(self):
        set_read_only_mode(enabled=True)
        paths = [
            "/login",
            "/logout",
            "/complete/github/",
            "/oauth2/idpresponse",
            "/password_reset/",
            "/reset/a/b/",
            "/forgot_username",
            "/change_password",
            "/api/v2/api-token-auth/",
            "/system_settings",
            "/api/v2/system_settings/1/",
        ]
        for path in paths:
            with self.subTest(path=path):
                response = rf_middleware(path)
                self.assertEqual(200, response.status_code)
                self.assertEqual(b"OK", response.content)

    def test_lock_and_unlock_through_api(self):
        settings_url = f"/api/v2/system_settings/{System_Settings.objects.get(no_cache=True).id}/"
        self.assertEqual(200, self.api.patch(settings_url, {"read_only_mode": True}, format="json").status_code)
        self.assertEqual(423, self.create_product_type("During lock").status_code)
        self.assertEqual(200, self.api.patch(settings_url, {"read_only_mode": False}, format="json").status_code)
        self.assertEqual(201, self.create_product_type("After unlock").status_code)

    def test_lock_change_seen_by_next_request(self):
        # update() fires no post_save, like a save in another worker process.
        system_settings = System_Settings.objects.filter(pk=System_Settings.objects.get(no_cache=True).pk)
        system_settings.update(read_only_mode=False)
        self.assertEqual(201, self.create_product_type("Before lock").status_code)
        system_settings.update(read_only_mode=True)
        self.assertEqual(423, self.create_product_type("During lock").status_code)
        system_settings.update(read_only_mode=False)
        self.assertEqual(201, self.create_product_type("After lock").status_code)

    @override_settings(SETTINGS_CACHE_L1_TTL=30)
    def test_no_extra_query_on_write(self):
        set_read_only_mode(enabled=False)
        get_cached_system_settings()
        with self.assertNumQueries(0):
            response = rf_middleware("/api/v2/product_types/")
        self.assertEqual(200, response.status_code)


PROBE_CALLS = []


@app.task
def read_only_beat_probe():
    PROBE_CALLS.append("beat")


@app.task
def read_only_plain_probe():
    PROBE_CALLS.append("plain")


@versioned_fixtures
@override_settings(CELERY_BEAT_SCHEDULE={"probe": {"task": read_only_beat_probe.name, "schedule": 60}})
class TestReadOnlyModeBeatTasks(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        PROBE_CALLS.clear()

    def test_beat_task_skipped_when_locked(self):
        set_read_only_mode(enabled=True)
        read_only_beat_probe()
        self.assertEqual([], PROBE_CALLS)

    def test_beat_task_runs_when_off(self):
        set_read_only_mode(enabled=False)
        read_only_beat_probe()
        self.assertEqual(["beat"], PROBE_CALLS)

    def test_non_beat_task_runs_when_locked(self):
        set_read_only_mode(enabled=True)
        read_only_plain_probe()
        self.assertEqual(["plain"], PROBE_CALLS)


READ_ONLY_BANNER = {"source": "read_only_mode", "message": str(READ_ONLY_MODE_MESSAGE), "style": "warning"}


@versioned_fixtures
class TestReadOnlyModeBanner(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def test_banner_in_context_when_locked(self):
        set_read_only_mode(enabled=True)
        context = globalize_vars(RequestFactory().get("/"))
        self.assertEqual(READ_ONLY_BANNER, context["additional_banners"][0])

    def test_no_banner_when_off(self):
        set_read_only_mode(enabled=False)
        context = globalize_vars(RequestFactory().get("/"))
        sources = [banner["source"] for banner in context.get("additional_banners", [])]
        self.assertNotIn("read_only_mode", sources)

    def test_banner_renders_on_home(self):
        set_read_only_mode(enabled=True)
        self.client.force_login(User.objects.get(username="admin"))
        response = self.client.get(reverse("home"), follow=True)
        self.assertContains(response, str(READ_ONLY_MODE_MESSAGE))
