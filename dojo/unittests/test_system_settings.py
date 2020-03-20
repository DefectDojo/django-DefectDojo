from django.test import TestCase
from dojo.models import System_Settings


class TestSystemSettings(TestCase):

    def test_system_settings_update(self):
        system_settings = System_Settings.objects.get()
        system_settings.enable_jira = True
        system_settings.save()
        system_settings = System_Settings.objects.get()
        self.assertEquals(system_settings.enable_jira, True)

        system_settings.enable_jira = False
        system_settings.save()
        system_settings = System_Settings.objects.get()
        self.assertEquals(system_settings.enable_jira, False)

        system_settings.enable_jira = True
        system_settings.save()
        system_settings = System_Settings.objects.get(no_cache=True)
        self.assertEquals(system_settings.enable_jira, True)
