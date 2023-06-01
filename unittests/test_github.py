import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dojo.settings.settings')
import django
django.setup()
from django.conf import settings
from django.core import management

import unittest
from unittest.mock import patch, Mock
import unittest.mock as mock
from dojo.github import *
from dojo.models import Engagement, Product, GITHUB_PKey, GITHUB_Issue, Product_Type, GITHUB_Conf, Finding, Test, Test_Type, User, SLA_Configuration
import datetime

from unittest.mock import MagicMock

class TestGitHub(unittest.TestCase):

    def setUp(self):
        prod_type, _ = Product_Type.objects.get_or_create(name="product_type")
        sla_conf, _ = SLA_Configuration.objects.get_or_create(name="SLA Configuration")
        Product.objects.filter(name="ProductTestGithub").delete()
        self.prod, _ = Product.objects.get_or_create(
            name="ProductTestGithub",
            prod_type=prod_type,
            sla_configuration=sla_conf
        )

        self.engagement = Engagement.objects.create(product=self.prod, target_start=datetime.datetime.now(),
                                                    target_end=datetime.datetime.now())
        github_conf = GITHUB_Conf.objects.create(api_key='dummy_api_key')
        self.github_pkey = GITHUB_PKey.objects.create(product=self.prod, git_conf=github_conf,
                                                      git_project='dummy_project')
        self.test_type, _ = Test_Type.objects.get_or_create(name="test type")


    @patch('dojo.github.GITHUB_PKey.objects.filter')
    def test_reopen_external_issue_github_no_github_info(self, mock_pkey_filter):
        prod = Mock()
        find = Mock()
        eng = Mock()
        note = "This issue has been reopened"
        result = reopen_external_issue_github(find, note, prod, eng)
        self.assertIsNone(result)


   
if __name__ == '__main__':
    unittest.main()