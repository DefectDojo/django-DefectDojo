from rest_framework.test import APITestCase, APIClient
from django.urls import reverse
from rest_framework.authtoken.models import Token


class UserTest(APITestCase):
    """
    Test the User APIv2 endpoint.
    """
    fixtures = ['dojo_testdata.json']

    def setUp(self):
        token = Token.objects.get(user__username='admin')
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

    def test_user_multiple_usernames(self):
        from django.urls import get_resolver
        r = self.client.get("{}?username=user1&username=user2".format(reverse('dojo_user-list')), format='json')
        self.assertEqual(r.status_code, 200, r.content[:1000])
        self.assertEqual(r.json()['count'], 2, r.content[:1000])
        self.assertEqual(r.json()['results'][0]['username'], 'user1', r.json()['results'][0])
        self.assertEqual(r.json()['results'][1]['username'], 'user2', r.json()['results'][1])
