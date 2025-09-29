import json
from django.test import TestCase
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient
from rest_framework import status
from unittest.mock import patch 

from dojo.models import (
    Product, 
    Engagement, 
    Test, 
    Finding,
    GeneralSettings,
    Product_Type,
)


class SecurityPostureAPITest(TestCase):
    fixtures = ['dojo_testdata.json']
    
    def setUp(self):
        """Initial configuration for tests"""
        self.client = APIClient()
        
        # Create test user
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        self.url = reverse('security_posture')
        
        # Create test data
        self.product_type = Product_Type.objects.get(id=1)
        self.product = Product.objects.first()
        self.engagement = Engagement.objects.first()
        self.engagement.name = "Test Engagement for Security Posture"
        self.engagement.save()
        self.test = Test.objects.first()
        
        # Create test findings
        self.critical_finding = Finding.objects.create(
            title="Critical Security Issue",
            test=self.test,
            severity="Critical",
            description="A critical security vulnerability",
            active=True,
            verified=True,
            false_p=False,
            duplicate=False
        )
        self.critical_finding.save()
        
        self.high_finding = Finding.objects.create(
            title="High Security Issue",
            test=self.test,
            severity="High", 
            description="A high security vulnerability",
            active=True,
            verified=True,
            false_p=False,
            duplicate=False
        )
        self.high_finding.save()
        
        
        self.medium_finding = Finding.objects.create(
            title="Medium Security Issue",
            test=self.test,
            severity="Medium",
            description="A medium security vulnerability",
            active=True,
            verified=True,
            false_p=False,
            duplicate=False
        )
        self.medium_finding.save()
        
        
        self.setup_general_settings()
        
        self.url = reverse('security_posture')

    def setup_general_settings(self):
        """Configure GeneralSettings for tests"""
        GeneralSettings.objects.get_or_create(
            name_key='SECURITY_POSTURE_STATUS',
            defaults={
                'value': '{"APETITO": 50, "TOLERANCIA": 100, "EXCEDIDO": 150}',
                'data_type': 'DICT'
            }
        )
        
        GeneralSettings.objects.get_or_create(
            name_key='HACKING_CONTINUOUS_TAGS',
            defaults={
                'value': '["hacking_continuous", "red_team", "pentest"]',
                'data_type': 'LIST'
            }
        )
        
        GeneralSettings.objects.get_or_create(
            name_key='DEVSECOPS_ADOPTION_EXCLUDE_TAGS',
            defaults={
                'value': '["transferred", "duplicated", "false_positive"]',
                'data_type': 'LIST'
            }
        )
        
        GeneralSettings.objects.get_or_create(
            name_key='HACKING_CONTINUOUS_DAYS_TOLERANCE',
            defaults={
                'value': '30',
                'data_type': 'INT'
            }
        )

    def test_get_security_posture_with_engagement_id(self):
        """Test get security posture with valid engagement_id"""
        response = self.client.get(
            self.url,
            {'engagement_id': self.engagement.id},
            format='json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('data', response.json())
        
        data = response.json()['data']
        self.assertEqual(data['engagement_name'], self.engagement.name)
        self.assertEqual(data['engagement_id'], self.engagement.id)
        self.assertEqual(data['severity_product'], self.product.business_criticality)
        self.assertIn('counter_active_findings', data)
        self.assertIn('counter_very_critical', data)
        self.assertIn('counter_critical', data)
        self.assertIn('counter_medium_low', data)
        self.assertIn('counter_info', data)


    def test_get_security_posture_with_engagement_name(self):
        """Test get security posture with valid engagement_name"""
        response = self.client.get(
            f"{self.url}?engagement_name={self.engagement.name}",
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()['data']
        self.assertEqual(data['engagement_name'], self.engagement.name)

    def test_get_security_posture_missing_parameters(self):
        """Test error when required parameters are missing"""
        response = self.client.get(self.url, format='json')
        print("response", response.json())

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Either engagement_id or engagement_name must be provided', 
                     response.json()['data']["non_field_errors"])

    def test_get_security_posture_invalid_engagement_id(self):
        """Test error with non-existent engagement_id"""
        response = self.client.get(
            self.url,
            {'engagement_id': 99999},
            format='json'
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Invalid pk "99999" - object does not exist.',
                      response.json()['data']["engagement_id"])

    def test_get_security_posture_invalid_engagement_name(self):
        """Test error with non-existent engagement_name"""
        response = self.client.get(
            self.url,
            {'engagement_name': 'NonExistentEngagement'},
            format='json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_get_security_posture_findings_count(self):
        """Test that findings counts are correct"""
        response = self.client.get(
            self.url,
            {'engagement_id': self.engagement.id},
            format='json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()['data']
        
        self.assertEqual(data['counter_active_findings'], 9)
        self.assertEqual(data['counter_very_critical'], 1)
        self.assertEqual(data['counter_critical'], 7)
        self.assertEqual(data['counter_medium_low'], 0)
        self.assertEqual(data['counter_info'], 0)

