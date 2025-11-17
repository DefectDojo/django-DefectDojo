from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.timezone import now

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
        self.product = Product.objects.create(name="Test Product", prod_type=self.product_type)
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
