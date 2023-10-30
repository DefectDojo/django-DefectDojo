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

    def test_user_list(self):
        r = self.client.get(reverse('user-list'))
        self.assertEqual(r.status_code, 200, r.content[:1000])
        user_list = r.json()['results']
        self.assertTrue(len(user_list) >= 1, r.content[:1000])
        for user in user_list:
            for item in ['username', 'first_name', 'last_name', 'email']:
                self.assertIn(item, user, r.content[:1000])
            for item in ['password']:
                self.assertNotIn(item, user, r.content[:1000])

    def test_user_add(self):
        # simple user without password
        r = self.client.post(reverse('user-list'), {
            "username": "api-user-1"
        }, format='json')
        self.assertEqual(r.status_code, 201, r.content[:1000])

        # user with good password
        password = 'testTEST1234!@#$'
        r = self.client.post(reverse('user-list'), {
            "username": "api-user-2",
            "password": password
        }, format='json')
        self.assertEqual(r.status_code, 201, r.content[:1000])

        # test password by fetching API key
        r = self.client.post(reverse('api-token-auth'), {
            "username": "api-user-2",
            "password": password
        }, format='json')
        self.assertEqual(r.status_code, 200, r.content[:1000])

        # user with weak password
        r = self.client.post(reverse('user-list'), {
            "username": "api-user-3",
            "password": "weakPassword"
        }, format='json')
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertIn('Password must contain at least 1 digit, 0-9.', r.content.decode("utf-8"))

    def test_user_change_password(self):
        # some user
        r = self.client.post(reverse('user-list'), {
            "username": "api-user-4"
        }, format='json')
        self.assertEqual(r.status_code, 201, r.content[:1000])
        user_id = r.json()['id']

        r = self.client.put("{}{}/".format(reverse('user-list'), user_id), {
            "username": "api-user-4",
            "first_name": "first"
        }, format='json',)
        self.assertEqual(r.status_code, 200, r.content[:1000])

        r = self.client.patch("{}{}/".format(reverse('user-list'), user_id), {
            "last_name": "last"
        }, format='json')
        self.assertEqual(r.status_code, 200, r.content[:1000])

        r = self.client.put("{}{}/".format(reverse('user-list'), user_id), {
            "username": "api-user-4",
            "password": "testTEST1234!@#$"
        }, format='json')
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertIn("Update of password though API is not allowed", r.content.decode("utf-8"))

        r = self.client.patch("{}{}/".format(reverse('user-list'), user_id), {
            "password": "testTEST1234!@#$"
        }, format='json')
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertIn("Update of password though API is not allowed", r.content.decode("utf-8"))
