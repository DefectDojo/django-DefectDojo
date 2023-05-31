import django
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dojo.settings.settings')
django.setup()

from dojo.tools.api_sonarqube.updater_from_source import *
from dojo.risk_acceptance.helper import remove_finding_from_risk_acceptance
from dojo.models import User, Finding, Test, Sonarqube_Issue, Development_Environment, Engagement, Product, Product_Type, Test_Type, Dojo_User
from django.utils import timezone
from unittest.mock import MagicMock
import unittest
from unittest.mock import patch



class TestSonarQubeApiUpdaterFromSource(unittest.TestCase):

    def setUp(self):
        self.updater = SonarQubeApiUpdaterFromSource()

        self.development_environment = Development_Environment(name="Production")
        self.development_environment.save()
        product_type, _ = Product_Type.objects.get_or_create(name="Product Type")

        # Obtain or create an instance of Dojo_User
        
        self.user, _ = User.objects.get_or_create(username="User 1")
    

        # Create a new instance of Product and assign the product_manager
        self.product, created = Product.objects.get_or_create(
            name="TestDojoDefaultImporter",
            prod_type=product_type,
        )

        

        self.product.save()

        self.engagement = Engagement(
            name="Engagement 1",
            target_start=timezone.now(),
            target_end=timezone.now(),
            description="Engagement description",
            product=self.product,
        )
        self.engagement.save()
        self.test_type, _ = Test_Type.objects.get_or_create(name="Test type")

        self.test = Test(
            title="Test 1",
            target_start=timezone.now(),
            target_end=timezone.now(),
            environment=self.development_environment,
            engagement=self.engagement,
            test_type=self.test_type,
        )
        self.test.save()

        self.sonarqube_issue, _ = Sonarqube_Issue.objects.get_or_create(
            key="test_key",
            status="Open",
            type="Vulnerability",
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
            reporter=self.user
        )
        self.finding.save()

    def tearDown(self):
        self.finding.delete()
        self.sonarqube_issue.delete()
        self.test.delete()
        self.engagement.delete()
        self.development_environment.delete()
        self.product.delete()

    def test_get_findings_to_update(self):
        self.assertEqual(len(self.updater.get_findings_to_update()), 1)

        finding_no_issue = Finding(
            test=self.test,
            active=True,
            verified=True,
            false_p=False,
            mitigated=None,
            is_mitigated=False,
            reporter=self.user
        )
        finding_no_issue.save()

        self.assertEqual(len(self.updater.get_findings_to_update()), 1)

    """
    @patch('dojo.tools.api_sonarqube.updater_from_source.SonarQubeApiImporter.prepare_client')
    
    def test_update(self, mock_prepare_client):
        # Mock data
        sonarqube_issue = Sonarqube_Issue(key='ABC-123')
        self.finding.sonarqube_issue = sonarqube_issue
        issue = {'resolution': 'FIXED'}

        # Mock the prepare_client method
        mock_client = mock_prepare_client.return_value
        mock_client.get_issue.return_value = issue

        # Configure the return value of mock_prepare_client
        mock_prepare_client.return_value = (mock_client, "some_other_value")

        # Create an instance of SonarQubeApiUpdaterFromSource
        updater = SonarQubeApiUpdaterFromSource()

        # Call the update method
        updater.update(self.finding)

        # Assert that the update_finding_status method is called with the correct arguments
        mock_client.get_issue.assert_called_once_with('ABC-123')
        mock_client.update_finding_status.assert_called_once_with(self.finding, 'FIXED')
    """



if __name__ == '__main__':
    unittest.main()
