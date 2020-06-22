import os.path

from django.test import TestCase
from dojo.tools.
from dojo.models import Test


def sample_path(file_name):
    return os.path.join('dojo/unittests/scans/awssecurityhub', file_name)


class AwsSecurityFindingFormatParser(TestCase):

    def setUp(self):
        self.dojo_test = Test()

    def test_no_findings(self):
        pass

    def test_one_finding(self):
        pass

    def test_many_findings(self):
        pass
