from django.core.management import call_command
from django.test import tag as test_tag

from .dojo_test_case import DojoTestCase


@test_tag("non-parallel")
class TestSampleData(DojoTestCase):
    def test_loaddata(self):
        try:
            call_command("loaddata", "dojo/fixtures/defect_dojo_sample_data", verbosity=0)
        except Exception as e:
            self.assertEqual(False, True, e)
        self.assertEqual(True, True)
