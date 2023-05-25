import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dojo.settings.settings')
import django
django.setup()
import os
from django.conf import settings
from django.core import management


import unittest
from unittest.mock import patch, Mock
import unittest.mock as mock
from dojo.github import *
from dojo.models import Engagement, Product, GITHUB_PKey, GITHUB_Issue

class TestGitHub(unittest.TestCase):

    @patch('dojo.github.GITHUB_PKey.objects.filter')
    def test_reopen_external_issue_github_no_github_info(self, mock_pkey_filter):
        mock_pkey_filter.return_value.count.return_value = 0
        prod = Mock()
        find = Mock()
        eng = Mock()
        note = "This issue has been reopened"
        result = reopen_external_issue_github(find, note, prod, eng)
        self.assertIsNone(result)

 

    @patch('dojo.utils.get_system_setting')
    @patch('dojo.github.GITHUB_PKey.objects.filter')
    @patch('dojo.github.GITHUB_PKey.objects.get')
    @patch('dojo.github.GITHUB_Issue.objects.get')
    @patch('dojo.github.Github')
    def test_reopen_external_issue_github_success(self, mock_github, mock_issue_get, mock_pkey_get, mock_pkey_filter, mock_get_system_setting):
        mock_get_system_setting.return_value = True
        mock_pkey_filter.return_value.count.return_value = 1
        mock_pkey_get.return_value = Mock(git_conf=Mock(api_key='dummy_api_key'), git_project='dummy_project')
        mock_issue_get.return_value = Mock(issue_id='1')
        mock_issue = Mock(state='closed')
        mock_issue.edit.return_value = None
        mock_issue.create_comment.return_value = None
        mock_repo = Mock()
        mock_repo.get_issue.return_value = mock_issue
        mock_github.return_value.get_repo.return_value = mock_repo

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
        mock_github.return_value.get_repo.assert_called_once_with('dummy_project')
        mock_repo.get_issue.assert_called_once_with(1)
        mock_issue.edit.assert_called_once_with(state='open')
        mock_issue.create_comment.assert_called_once_with(note)