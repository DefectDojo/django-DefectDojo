from rest_framework.test import APITestCase, APIClient
from django.urls import reverse
from rest_framework.authtoken.models import Token


class NotificationsTest(APITestCase):
    """
    Test the metadata APIv2 endpoint.
    """
    fixtures = ['dojo_testdata.json']

    def setUp(self):
        token = Token.objects.get(user__username='admin')
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

        r = self.create(
            template=True,
            scan_added=['alert', 'slack']
        )
        self.assertEqual(r.status_code, 201)

    def create(self, **kwargs):
        return self.client.post(reverse('notifications-list'), kwargs, format='json')

    def test_notification_get(self):
        r = self.client.get(reverse('notifications-list'), format='json')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['results'][0]['template'], False)

    def test_notification_template(self):
        q = {'template': True}
        r = self.client.get(reverse('notifications-list'), q, format='json')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['results'][0]['template'], True)

    def test_notification_template_multiple(self):
        q = {'template': True, 'scan_added': ['alert', 'slack']}
        r = self.client.post(reverse('notifications-list'), q, format='json')
        self.assertEqual("Notification template already exists", r.json()["non_field_errors"][0])
