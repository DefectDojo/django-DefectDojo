
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




django.setup()


class TestReportsViews(unittest.TestCase):
    def setUp(self):
        self.factory = RequestFactory()

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
