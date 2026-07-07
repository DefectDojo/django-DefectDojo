from unittest import mock

from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils.timezone import now

from dojo.caching import invalidate_dojo_settings_cache, reset_l1_cache
from dojo.middleware import SYSTEM_SETTINGS_CACHE_KEY, DojoSettingsManagerMiddleware, get_cached_system_settings
from dojo.models import (
    Engagement,
    Finding,
    Product,
    Product_Type,
    System_Settings,
    Test,
    Test_Type,
    User,
)

from .dojo_test_case import DojoTestCase


class TestSystemSettings(DojoTestCase):

    def test_system_settings_update(self):
        try:
            # although the unittests are run after initial data has been loaded, for some reason in cicd sometimes the settings aren't present
            system_settings = System_Settings.objects.get(no_cache=True)
        except System_Settings.DoesNotExist:
            system_settings = System_Settings()

        system_settings.enable_jira = True
        system_settings.save()
        system_settings = System_Settings.objects.get(no_cache=True)
        self.assertEqual(system_settings.enable_jira, True)

        system_settings.enable_jira = False
        system_settings.save()
        system_settings = System_Settings.objects.get(no_cache=True)
        self.assertEqual(system_settings.enable_jira, False)

        system_settings.enable_jira = True
        system_settings.save()
        system_settings = System_Settings.objects.get(no_cache=True)
        self.assertEqual(system_settings.enable_jira, True)


@override_settings(DD_EDITABLE_MITIGATED_DATA=True)
class CloseFindingViewInstanceTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="tester",
            password="pass",  # noqa: S106
            is_staff=True,
            is_superuser=True,
        )
        self.client.force_login(self.user)
        self.product_type = Product_Type.objects.create(name="Test Product Type")
        self.product = Product.objects.create(name="Test Product", description="test", prod_type=self.product_type)
        self.engagement = Engagement.objects.create(
            name="Test Engagement",
            product=self.product,
            target_start=now(),
            target_end=now(),
        )
        self.test_type = Test_Type.objects.create(name="Unit Test Type")
        self.test = Test.objects.create(
            engagement=self.engagement,
            test_type=self.test_type,
            title="Test for Finding",
            target_start=now(),
            target_end=now(),
        )
        self.finding = Finding.objects.create(
            title="Close Finding Test",
            active=True,
            test=self.test,
            reporter=self.user,
        )
        self.url = reverse("close_finding", args=[self.finding.id])

    def test_get_request_initializes_form_with_finding_instance(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        form = response.context["form"]
        self.assertIsInstance(form.instance, Finding)
        self.assertEqual(form.instance.id, self.finding.id)

    def test_post_request_initializes_form_with_finding_instance(self):
        data = {"close_reason": "Mitigated", "notes": "Closing this finding"}
        response = self.client.post(self.url, data)
        self.assertIn(response.status_code, [200, 302])


@override_settings(SETTINGS_CACHE_L1_TTL=30)
class TestSystemSettingsMiddlewareIntegration(DojoTestCase):

    """
    Integration tests for DojoSettingsManagerMiddleware + System_Settings_Manager.

    Caching lives in dojo.caching (in-process L1 decorator); the middleware resets
    the request-scoped L1 tier and surfaces a load error. These tests pin L1 on via
    override_settings so they don't depend on the compose env.
    """

    def setUp(self):
        super().setUp()
        self.factory = RequestFactory()

    def test_no_cache_always_hits_db(self):
        # no_cache bypasses both tiers: every read is a fresh query.
        with self.assertNumQueries(2):
            System_Settings.objects.get(no_cache=True)
            System_Settings.objects.get(no_cache=True)

    def test_repeated_cached_get_served_from_l1(self):
        # Cold start, warm once (1 query), then repeated cached reads do no queries.
        reset_l1_cache()
        invalidate_dojo_settings_cache(SYSTEM_SETTINGS_CACHE_KEY)
        with self.assertNumQueries(1):
            get_cached_system_settings()
        with self.assertNumQueries(0):
            s2 = System_Settings.objects.get()
            s3 = System_Settings.objects.get()
        # Rebuilt per call from the cached dict: equal data, not the same instance.
        self.assertEqual(s2.pk, s3.pk)

    def test_middleware_resets_l1_each_request(self):
        # Warm L1, change the row underneath via update() (no post_save signal, so
        # L1 is not auto-busted), then a request must still see the new value
        # because the middleware resets L1 at request start.
        get_cached_system_settings()
        System_Settings.objects.update(enable_deduplication=True)
        seen = []

        def view(_request):
            seen.append(System_Settings.objects.get().enable_deduplication)
            return HttpResponse("OK")

        middleware = DojoSettingsManagerMiddleware(view)
        middleware(self.factory.get("/test/"))
        self.assertEqual(seen, [True])

    def test_middleware_surfaces_load_error(self):
        # When the DB read fails, get_from_db stashes an error on the thread-local
        # and returns defaults; the middleware copies the error onto the request
        # for the banner context processor.
        invalidate_dojo_settings_cache(SYSTEM_SETTINGS_CACHE_KEY)
        reset_l1_cache()
        captured = {}

        def view(request):
            captured["err"] = getattr(request, "system_settings_error", None)
            return HttpResponse("OK")

        def failing_get_from_db(*args, **kwargs):
            DojoSettingsManagerMiddleware._thread_local.system_settings_error = "boom"
            return System_Settings()  # defaults (pk None) -> not cached

        middleware = DojoSettingsManagerMiddleware(view)
        with mock.patch.object(System_Settings.objects, "get_from_db", side_effect=failing_get_from_db):
            middleware(self.factory.get("/test/"))
        self.assertEqual(captured["err"], "boom")
