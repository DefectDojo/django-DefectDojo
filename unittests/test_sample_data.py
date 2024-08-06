from django.core.management import call_command
from django.test import tag as test_tag

from .dojo_test_case import DojoTestCase


@test_tag("non-parallel")
class TestSampleData(DojoTestCase):

    fixtures = ["defect_dojo_sample_data"]

    def test_loaddata(self):
        # this test running at all is indicative of the test passing
        # We will just assert True, and move on
        self.assertEqual(True, True)
