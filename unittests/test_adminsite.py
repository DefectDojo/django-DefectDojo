import django.apps
from django.contrib import admin

from .dojo_test_case import DojoTestCase


class AdminSite(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def test_is_model_defined(self):
        for subclass in django.apps.apps.get_models():
            if subclass._meta.proxy:
                continue
            if subclass.__module__ == "dojo.models":
                if not ((subclass.__name__[:9] == "Tagulous_") and (subclass.__name__[-5:] == "_tags")):
                    with self.subTest(type="base", subclass=subclass):
                        self.assertIn(subclass, admin.site._registry.keys(), f"{subclass} is not registered in 'admin.site' in models.py")
                else:
                    with self.subTest(type="tag", subclass=subclass):
                        self.assertIn(subclass, admin.site._registry.keys(), f"{subclass} is not registered in 'tagulous.admin' in models.py")
