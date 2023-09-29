import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dojo.settings.settings')
import django
django.setup()

import unittest
from unittest.mock import  patch
from django.test import RequestFactory
from django.contrib.auth.models import AnonymousUser
from django.http import HttpResponse
from dojo.reports.views import *
from unittest.mock import Mock
from dojo.models import User
from django.test import TestCase, Client
from django.urls import reverse


class ReportsViewsTestCase(TestCase):

    def setUp(self):
        self.factory = RequestFactory()
        self.client = Client()

    def test_down(self):
        request = self.factory.get('/down')
        request.user = AnonymousUser()

        with patch('dojo.reports.views.render') as mock_render:
            mock_render.return_value = HttpResponse(status=200)
            response = down(request)
            mock_render.assert_called_with(request, 'disabled.html')
            self.assertEqual(response.status_code, 200)

    def test_report_url_resolver_with_forwarded_headers(self):
        request = self.factory.get('/')
        request.META = {
            'HTTP_X_FORWARDED_PROTO': 'https',
            'HTTP_X_FORWARDED_FOR': 'example.com',
            'SERVER_PORT': '8000'
        }
        expected_url_resolver = 'https://example.com:8000'
        url_resolver = report_url_resolver(request)
        self.assertEqual(url_resolver, expected_url_resolver)


    def test_report_url_resolver_without_forwarded_headers(self):
        request = self.factory.get('/')
        request.META = {
            'HTTP_HOST': 'example.com:8000',
            'SERVER_PORT': '8000',
            'scheme': 'http'
        }
        expected_url_resolver = 'http://example.com:8000'

        with patch.dict('dojo.reports.views.__dict__', {'request': request}):
            url_resolver = report_url_resolver(request)

        self.assertEqual(url_resolver, expected_url_resolver)



if __name__ == '__main__':
    unittest.main()
