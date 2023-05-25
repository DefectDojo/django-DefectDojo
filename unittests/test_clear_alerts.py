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



   