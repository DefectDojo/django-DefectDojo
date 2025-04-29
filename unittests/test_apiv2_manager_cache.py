from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework.authtoken.models import Token
from django.core.cache import cache
from unittest.mock import MagicMock, patch


class TestManagerCacheApiView(APITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        self.url = '/api/v2/manager-cache/'
        self.pattern = 'test-pattern*'
        self.redis_client_mock = MagicMock()
        self.redis_client_mock.scan_iter.return_value = [b'test-key-1', b'test-key-2']
        self.redis_client_mock.delete.return_value = "OK"

    @patch('dojo.api_v2.manager_cache.views.cache')
    def test_get_keys_success(self, cache_mock):
        cache_mock.client.get_client.return_value = self.redis_client_mock
        response = self.client.get(self.url, {'pattern': self.pattern})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('List Key Cache', response.data['message'])
        self.assertEqual(response.data['data'], ['test-key-1', 'test-key-2'])

    def test_get_keys_invalid_serializer(self):
        response = self.client.get(self.url, {'invalid_field': 'value'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Invalid serializer', response.data['message'])

    @patch('dojo.api_v2.manager_cache.views.cache')
    def test_post_delete_keys_success(self, cache_mock):
        cache_mock.client.get_client.return_value = self.redis_client_mock
        response = self.client.post(self.url, query_params={'pattern': self.pattern})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('Deleted Key Cache', response.data['message'])

    def test_post_delete_keys_invalid_serializer(self):
        response = self.client.post(self.url, {'invalid_field': 'value'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Invalid serializer', response.data['message'])
