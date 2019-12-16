import os.path

from django.test import TestCase
from dojo.tools.trivy.parser import TrivyParser
from dojo.models import Test


def sample_path(file_name):
    return os.path.join('dojo/unittests/scans/trivy', file_name)


class TestTrivyParser(TestCase):

    def setUp(self):
        self.dojo_test = Test()

    def test_mixed_scan(self):
        with open(sample_path('trivy_mix.json')) as test_file:
            trivy_parser = TrivyParser(test_file, self.dojo_test)
        self.assertEqual(len(trivy_parser.items), 6)
