import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dojo.settings.settings')
import django
django.setup()

import unittest
from unittest.mock import patch
from django.test import TestCase
from django.utils import timezone
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

    


    """def test_get_findings_to_update(self):
        findings = [self.finding1, self.finding2, self.finding3, self.finding4]

        mock_query = MagicMock()
        mock_query.select_related.return_value = findings

        with patch.object(Finding.objects, 'filter', return_value=mock_query) as mock_filter:
            updated_findings = SonarQubeApiUpdaterFromSource.get_findings_to_update()

            mock_filter.assert_called_with(
                sonarqube_issue__isnull=False,
                active=True,
            )
            mock_query.select_related.assert_called_with('sonarqube_issue')
            self.assertEqual(updated_findings, findings)"""



if __name__ == '__main__':
    unittest.main()
