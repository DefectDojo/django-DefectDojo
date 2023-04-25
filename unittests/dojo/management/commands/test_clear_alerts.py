import django
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dojo.settings.settings')
django.setup()

from unittest import TestCase
from argparse import ArgumentParser
from django.core.management.base import CommandParser
from dojo.management.commands.clear_alerts import Command

class RemoveAlertsTest(TestCase):
    def setUp(self):
        self.command = Command()
        self.parser = ArgumentParser()
        self.command.add_arguments(self.parser)

    def test_add_arguments(self):
        self.assertIn('-a', [action.option_strings[0] for action in self.parser._actions])
        self.assertIn('-s', [action.option_strings[0] for action in self.parser._actions])
        self.assertIn('-u', [action.option_strings[0] for action in self.parser._actions])



    """
    def test_handle_with_all_argument(self):
        with patch('dojo.management.commands.remove_alerts.call_command') as mock_call_command:
            self.cmd.handle(all=True, system=False, users=None)
            mock_call_command.assert_called_with('delete_alerts', all=True)

    def test_handle_with_system_argument(self):
        with patch('dojo.management.commands.remove_alerts.call_command') as mock_call_command:
            self.cmd.handle(all=False, system=True, users=None)
            mock_call_command.assert_called_with('delete_alerts', system=True)

    def test_handle_with_users_argument(self):
        with patch('dojo.management.commands.remove_alerts.call_command') as mock_call_command:
            self.cmd.handle(all=False, system=False, users=['user1', 'user2'])
            mock_call_command.assert_called_with('delete_alerts', users=['user1', 'user2'])

    def test_handle_with_no_arguments(self):
        with self.assertRaises(CommandError):
            self.cmd.handle(all=False, system=False, users=None)
            """