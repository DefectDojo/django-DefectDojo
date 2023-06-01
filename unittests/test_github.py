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


    """@patch('dojo.utils.get_system_setting')
    @patch('dojo.github.GITHUB_PKey.objects.filter')
    @patch('dojo.github.GITHUB_PKey.objects.get')
    @patch('dojo.github.GITHUB_Issue.objects.get')
    @patch('dojo.github.Github')
    def test_reopen_external_issue_github_success(self, mock_github, mock_issue_get, mock_pkey_get,
                                                mock_pkey_filter, mock_get_system_setting):
        mock_get_system_setting.return_value = True
        mock_pkey_get.return_value = Mock(git_conf=Mock(api_key='dummy_api_key'), git_project='dummy_project')
        mock_pkey_filter.return_value.count.return_value = Mock(count=1)

        mock_issue_get.return_value = Mock(issue_id='1')
        mock_issue = Mock(state='closed')
        mock_issue.edit.return_value = None
        mock_issue.create_comment.return_value = None
        mock_repo = Mock()
        mock_repo.get_issue.return_value = mock_issue
        mock_github_instance = Mock()
        mock_github_instance.get_repo.return_value = mock_repo
        mock_github.return_value = mock_github_instance

        prod = Mock()
        find = Mock()
        eng = Mock()
        note = "This issue has been reopened"

        reopen_external_issue_github(find, note, prod, eng)

        mock_get_system_setting.assert_called_once_with('enable_github')
        mock_pkey_filter.assert_called_once_with(product=prod)
        mock_pkey_get.assert_called_once_with(product=prod)
        mock_issue_get.assert_called_once_with(finding=find)
        mock_github.assert_called_once_with('dummy_api_key')
        mock_github_instance.get_repo.assert_called_once_with('dummy_project')
        mock_repo.get_issue.assert_called_once_with(1)
        mock_issue.edit.assert_called_once_with(state='open')
        mock_issue.create_comment.assert_called_once_with('This issue has been reopened')"""



    """@patch('dojo.utils.get_system_setting')
    @patch('dojo.github.GITHUB_PKey.objects.filter')
    @patch('dojo.github.GITHUB_PKey.objects.get')
    @patch('dojo.github.GITHUB_Issue.objects.get')
    @patch('dojo.github.Github')
    def test_close_external_issue_github_success(self, mock_github, mock_issue_get, mock_pkey_get,
                                                mock_pkey_filter, mock_get_system_setting):
        mock_get_system_setting.return_value = True
        mock_pkey_get.return_value = Mock(git_conf=Mock(api_key='dummy_api_key'), git_project='dummy_project')
        mock_issue_get.return_value = Mock(issue_id='1')
        mock_issue = Mock(state='open')
        mock_issue.edit.return_value = None
        mock_issue.create_comment.return_value = None
        mock_repo = Mock()
        mock_repo.get_issue.return_value = mock_issue
        mock_github.return_value = Mock()
        mock_github.return_value.get_repo.return_value = mock_repo

        prod = Mock()
        find = Mock()
        eng = Mock()
        note = "This issue has been closed"

        close_external_issue_github(find, note, prod, eng)

        mock_get_system_setting.assert_called_once_with('enable_github')
        mock_pkey_filter.assert_called_once_with(product=prod)
        mock_pkey_get.assert_called_once_with(product=prod)
        mock_issue_get.assert_called_once_with(finding=find)
        mock_github.assert_called_once_with('dummy_api_key')
        mock_github.return_value.get_repo.assert_called_once_with('dummy_project')
        mock_repo.get_issue.assert_called_once_with(1)
        mock_issue.edit.assert_called_once_with(state='closed')
        mock_issue.create_comment.assert_called_once_with('This issue has been closed')"""

if __name__ == '__main__':
    unittest.main()