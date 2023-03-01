from .dojo_test_case import DojoTestCase
from dojo import models


class AdminSite(DojoTestCase):
    fixtures = ['dojo_testdata.json']

    def test_is_model_defined(self):
        for subclass in models.Model.__subclasses__():
            if subclass.__module__ == 'dojo.models':
                with self.subTest(subclass=subclass):
                    self.assertIn(subclass, models.admin.site._registry.keys())
