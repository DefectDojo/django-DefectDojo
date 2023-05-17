
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dojo.settings.settings')
import django
django.setup()


from dojo.reports.views import *
from django.test import RequestFactory
from django.contrib.auth.models import User
import unittest
import unittest.mock
from unittest.mock import patch
from unittest.mock import MagicMock
from unittest.mock import Mock
from django.template.response import TemplateResponse

from django.urls import reverse


django.setup()


class TestReportsViews(unittest.TestCase):
    @classmethod
   

    def setUp(self):
        self.factory = RequestFactory()
        self.request = self.factory.get(reverse('report_builder'))
        self.user = User.objects.get(username='testuser') # retrieve the existing user
        self.request.user = self.user


    def test_down_view(self):
        request = self.factory.get('/dojo/reports/views/down/')
        username = 'testuser'
        user, created = User.objects.get_or_create(username=username)
        request.user = user
        response = down(request)
        self.assertEqual(response.status_code, 200)
        # Add more assertions as necessary

    def test_report_url_resolver(self):
        request = MagicMock()
        request.META = {
            'HTTP_X_FORWARDED_PROTO': 'https',
            'HTTP_X_FORWARDED_FOR': '192.0.2.1',
            'HTTP_HOST': 'example.com:8000',
            'SERVER_PORT': '8000',
            'scheme': 'http'
        }

        url = report_url_resolver(request)

        self.assertEqual(url, 'https://192.0.2.1:8000')

    def test_except_report_url_resolver(self):
        request = MagicMock()
        request.META = {
            'HTTP_HOST': 'example.com:8000',
            'SERVER_PORT': '8000',
        }
        request.scheme = 'http'

        url = report_url_resolver(request)

        self.assertEqual(url, 'http://example.com:8000')



    def test_report_builder(self):
        self.request.session = {}
        self.request.user = self.user
        self.request.GET = QueryDict('')
        response = report_builder(self.request)

"""
    def test_custom_report(self):
            request = self.factory.post('/custom-report/', data={'json': '{}'})
            request.user = self.user
            request.META['HTTP_X_FORWARDED_PROTO'] = 'http'  # Agrega esta línea
            request.META['HTTP_HOST'] = 'localhost'  # Agrega esta línea
            
            response = custom_report(request)
            
            self.assertIsInstance(response, TemplateResponse)
            self.assertEqual(response.status_code, 200)
            self.assertTemplateUsed(response, 'dojo/custom_asciidoc_report.html')
            self.assertIn('widgets', response.context_data)
            self.assertIn('host', response.context_data)
            self.assertIn('finding_notes', response.context_data)
            self.assertIn('finding_images', response.context_data)
            self.assertIn('user_id', response.context_data)


    

"""