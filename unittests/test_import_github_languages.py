import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dojo.settings.settings')
import django
django.setup()

import unittest
from unittest.mock import patch, MagicMock
from dojo.management.commands.import_github_languages import Command
from dojo.models import Language_Type

class TestImportGitHubLanguagesCommand(unittest.TestCase):

    @patch('dojo.management.commands.import_github_languages.requests')
    def test_handle(self, mock_requests):
        mock_response = MagicMock()
        mock_response.text = '{"Python": {"color": "#3572A5"}, "Java": {"color": "#B07219"}}'
        mock_requests.get.return_value = mock_response

        command = Command()
        command.handle()

        self.assertEqual(Language_Type.objects.filter(language='Python').count(), 1)
        self.assertEqual(Language_Type.objects.get(language='Python').color, '#3572A5')
        self.assertEqual(Language_Type.objects.filter(language='Java').count(), 1)
        self.assertEqual(Language_Type.objects.get(language='Java').color, '#B07219')
