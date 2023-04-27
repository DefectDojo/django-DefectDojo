import django
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dojo.settings.settings')
django.setup()


from dojo.tools.api_sonarqube.updater_from_source import SonarQubeApiUpdaterFromSource
from dojo.risk_acceptance.helper import remove_finding_from_risk_acceptance
from dojo.models import Finding, Test, Sonarqube_Issue
from django.utils import timezone
from unittest.mock import MagicMock
import unittest


class TestSonarQubeApiUpdaterFromSource(unittest.TestCase):

    def setUp(self):
        self.updater = SonarQubeApiUpdaterFromSource()

        self.test = Test(
            title="Test 1",
            target_start=timezone.now(),
            target_end=timezone.now(),
            environment="production",
        )
        self.test.save()

        self.sonarqube_issue = Sonarqube_Issue(
            key="test_key",
            url="https://test.com",
        )
        self.sonarqube_issue.save()

        self.finding = Finding(
            test=self.test,
            sonarqube_issue=self.sonarqube_issue,
            active=True,
            verified=True,
            false_p=False,
            mitigated=None,
            is_mitigated=False,
            reporter=self.test.engagement.product.prod_manager,
        )
        self.finding.save()

        def tearDown(self):
            self.finding.delete()
            self.sonarqube_issue.delete()
            self.test.delete()

        def test_get_findings_to_update(self):
            self.assertEqual(len(self.updater.get_findings_to_update()), 1)

            # Ensure that findings without a Sonarqube issue aren't included
            finding_no_issue = Finding(
                test=self.test,
                active=True,
                verified=True,
                false_p=False,
                mitigated=None,
                is_mitigated=False,
                reporter=self.test.engagement.product.prod_manager,
            )
            finding_no_issue.save()

            self.assertEqual(len(self.updater.get_findings_to_update()), 1)

            finding_no_issue.delete()

            # Ensure that inactive findings aren't included
            self.finding.active = False
            self.finding.save()

            self.assertEqual(len(self.updater.get_findings_to_update()), 0)

            self.finding.active = True
            self.finding.save()
