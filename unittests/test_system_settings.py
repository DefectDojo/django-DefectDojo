from unittest.mock import Mock

from django.db import models
from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils.timezone import now

from dojo.middleware import DojoSytemSettingsMiddleware
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
            system_settings = System_Settings.objects.get()
        except System_Settings.DoesNotExist:
            system_settings = System_Settings()

        system_settings.enable_jira = True
        system_settings.save()
        system_settings = System_Settings.objects.get()
        self.assertEqual(system_settings.enable_jira, True)

        system_settings.enable_jira = False
        system_settings.save()
        system_settings = System_Settings.objects.get()
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


class TestSystemSettingsMiddlewareIntegration(DojoTestCase):

    """Integration tests for DojoSytemSettingsMiddleware using RequestFactory."""

    def setUp(self):
        """Set up test environment."""
        super().setUp()
        self.factory = RequestFactory()
        # Ensure signal is connected
        models.signals.post_save.disconnect(DojoSytemSettingsMiddleware.cleanup, sender=System_Settings)
        models.signals.post_save.connect(DojoSytemSettingsMiddleware.cleanup, sender=System_Settings)

    def test_middleware_loads_cache_on_request(self):
        """Test that middleware loads settings into cache when processing a request."""
        # Ensure cache is empty
        DojoSytemSettingsMiddleware.cleanup()
        self.assertIsNone(DojoSytemSettingsMiddleware.get_system_settings())

        # Create middleware with mock get_response
        mock_response = HttpResponse("OK")
        mock_get_response = Mock(return_value=mock_response)
        middleware = DojoSytemSettingsMiddleware(mock_get_response)

        # Create a request
        request = self.factory.get("/test/")

        # Process request through middleware
        response = middleware(request)

        # Verify response is returned
        self.assertEqual(response, mock_response)
        mock_get_response.assert_called_once_with(request)

        # Verify cache was populated during request processing
        # Note: cache should be cleaned up after request, but we can check during processing
        # Since cleanup happens in finally block, cache should be empty after __call__ returns
        self.assertIsNone(DojoSytemSettingsMiddleware.get_system_settings())

    def test_middleware_cleans_up_cache_after_request(self):
        """Test that middleware cleans up cache after request processing."""
        # Manually load cache first
        DojoSytemSettingsMiddleware.load()
        self.assertIsNotNone(DojoSytemSettingsMiddleware.get_system_settings())

        # Create middleware
        middleware = DojoSytemSettingsMiddleware(lambda _r: HttpResponse("OK"))

        # Process request
        request = self.factory.get("/test/")
        middleware(request)

        # Verify cache is cleaned up after request
        self.assertIsNone(DojoSytemSettingsMiddleware.get_system_settings())

    def test_middleware_cleans_up_cache_on_exception(self):
        """Test that middleware cleans up cache even when exception occurs."""
        # Load cache first
        DojoSytemSettingsMiddleware.load()
        self.assertIsNotNone(DojoSytemSettingsMiddleware.get_system_settings())

        # Create middleware that raises an exception
        def failing_get_response(request):
            msg = "Test exception"
            raise ValueError(msg)

        middleware = DojoSytemSettingsMiddleware(failing_get_response)

        # Process request - should raise exception
        request = self.factory.get("/test/")
        with self.assertRaises(ValueError):
            middleware(request)

        # Verify cache is cleaned up even after exception
        self.assertIsNone(DojoSytemSettingsMiddleware.get_system_settings())

    def test_middleware_process_exception_cleans_up_cache(self):
        """Test that process_exception method cleans up cache."""
        # Load cache first
        DojoSytemSettingsMiddleware.load()
        self.assertIsNotNone(DojoSytemSettingsMiddleware.get_system_settings())

        # Create middleware
        middleware = DojoSytemSettingsMiddleware(lambda _r: HttpResponse("OK"))

        # Call process_exception directly
        request = self.factory.get("/test/")
        exception = ValueError("Test exception")
        middleware.process_exception(request, exception)

        # Verify cache is cleaned up
        self.assertIsNone(DojoSytemSettingsMiddleware.get_system_settings())

    def test_middleware_cache_isolation_between_requests(self):
        """Test that cache is isolated between requests (thread-local)."""
        # Create middleware
        middleware = DojoSytemSettingsMiddleware(lambda _r: HttpResponse("OK"))

        # First request
        request1 = self.factory.get("/test1/")
        middleware(request1)
        self.assertIsNone(DojoSytemSettingsMiddleware.get_system_settings())

        # Second request - cache should be empty at start
        request2 = self.factory.get("/test2/")
        middleware(request2)
        self.assertIsNone(DojoSytemSettingsMiddleware.get_system_settings())

    def test_middleware_cache_during_request_processing(self):
        """Test that cache is available during request processing."""
        # Track if cache was available during request
        cache_available_during_request = []

        def get_response_with_cache_check(request):
            # Check if cache is available during request processing
            cached = DojoSytemSettingsMiddleware.get_system_settings()
            cache_available_during_request.append(cached is not None)
            return HttpResponse("OK")

        middleware = DojoSytemSettingsMiddleware(get_response_with_cache_check)

        # Process request
        request = self.factory.get("/test/")
        middleware(request)

        # Verify cache was available during request processing
        self.assertTrue(cache_available_during_request[0], "Cache should be available during request processing")

        # But cleaned up after request
        self.assertIsNone(DojoSytemSettingsMiddleware.get_system_settings())

    def test_multiple_get_calls_use_cache(self):
        """Test that multiple calls to System_Settings.objects.get() use cache instead of multiple DB queries."""
        # Ensure cache is empty
        DojoSytemSettingsMiddleware.cleanup()

        # First call should hit DB (cache is empty)
        with self.assertNumQueries(1):
            settings1 = System_Settings.objects.get()

        # Load into cache via middleware
        DojoSytemSettingsMiddleware.load()

        # Now multiple calls should use cache (no additional DB queries)
        with self.assertNumQueries(0):
            settings2 = System_Settings.objects.get()
            settings3 = System_Settings.objects.get()
            settings4 = System_Settings.objects.get()

        # All calls should return the same cached object instance
        self.assertEqual(settings1.id, settings2.id)
        self.assertEqual(settings2.id, settings3.id)
        self.assertEqual(settings3.id, settings4.id)
        # Verify they're the same object instance (same memory address)
        self.assertIs(settings2, settings3)
        self.assertIs(settings3, settings4)

    def test_multiple_get_calls_within_request_use_cache(self):
        """Test that multiple get() calls within a single request use cache."""
        retrieved_settings = []

        def get_response_with_multiple_gets(request):
            # Make multiple calls to get() during request processing
            retrieved_settings.append(System_Settings.objects.get())
            retrieved_settings.append(System_Settings.objects.get())
            retrieved_settings.append(System_Settings.objects.get())
            return HttpResponse("OK")

        middleware = DojoSytemSettingsMiddleware(get_response_with_multiple_gets)

        # Process request - should only hit DB once (when loading cache)
        # Then all subsequent get() calls should use cache
        request = self.factory.get("/test/")
        with self.assertNumQueries(1):  # Only one query to load settings into cache
            middleware(request)

        # Verify we got 3 settings objects
        self.assertEqual(len(retrieved_settings), 3)

        # All should be the same cached instance
        self.assertIs(retrieved_settings[0], retrieved_settings[1])
        self.assertIs(retrieved_settings[1], retrieved_settings[2])
        self.assertEqual(retrieved_settings[0].id, retrieved_settings[1].id)
