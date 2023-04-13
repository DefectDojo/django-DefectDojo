import django
django.setup()

from django.urls import reverse
from django.test import TestCase, Client
from django.contrib.auth.models import User
from unittest.mock import patch, MagicMock
from dojo.models import System_Settings, Dojo_User
from django.conf import settings


class DownViewTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser8',
            email='testuser@example.com',
            password='testpass'
        )
        self.client = Client()
        self.client.login(username='testuser8', password='testpass')
        

    def test_down_view(self):
        url = reverse('down')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

