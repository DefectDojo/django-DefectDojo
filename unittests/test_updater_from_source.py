import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dojo.settings.settings')
import django
django.setup()

import unittest
from django.test import TestCase
from dojo.models import Finding, Sonarqube_Issue
from dojo.tools.api_sonarqube.updater_from_source import *
from unittest.mock import MagicMock


class TestSonarQubeApiUpdater(TestCase):

    def setUp(self):
        self.sonarqube_issue = Sonarqube_Issue(key="ABC123", status="Open", type="Bug")
        self.finding1 = Finding(active=True, sonarqube_issue=self.sonarqube_issue)
        self.finding2 = Finding(active=True, sonarqube_issue=None)
        self.finding3 = Finding(active=False, sonarqube_issue=self.sonarqube_issue)
        self.finding4 = Finding(active=True, sonarqube_issue=self.sonarqube_issue)

        self.finding = MagicMock()
        self.finding.sonarqube_issue = MagicMock()
        self.finding.test = MagicMock()





if __name__ == '__main__':
    unittest.main()
