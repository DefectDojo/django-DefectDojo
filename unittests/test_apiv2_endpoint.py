from rest_framework.test import APITestCase, APIClient
from django.urls import reverse
from rest_framework.authtoken.models import Token


class EndpointTest(APITestCase):
    """
    Test the Endpoint APIv2 endpoint.
    """
    fixtures = ['dojo_testdata.json']

    def setUp(self):
        token = Token.objects.get(user__username='admin')
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)

    def test_endpoint_missing_host_product(self):
        r = self.client.post(reverse('endpoint-list'), {
            "host": "FOO.BAR"
        }, format='json')
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertIn("Attribute \'product\' is required", r.content.decode("utf-8"))

        r = self.client.post(reverse('endpoint-list'), {
            "product": 1
        }, format='json')
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertIn("Host must not be empty", r.content.decode("utf-8"))

    def test_endpoint_add_existing(self):
        r = self.client.post(reverse('endpoint-list'), {
            "product": 1,
            "host": "FOO.BAR"
        }, format='json')
        self.assertEqual(r.status_code, 201, r.content[:1000])

        r = self.client.post(reverse('endpoint-list'), {
            "product": 1,
            "host": "FOO.BAR"
        }, format='json')
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertIn('It appears as though an endpoint with this data already '
                      'exists for this product.', r.content.decode("utf-8"))

        r = self.client.post(reverse('endpoint-list'), {
            "product": 1,
            "host": "foo.bar"
        }, format='json')
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertIn('It appears as though an endpoint with this data already '
                      'exists for this product.', r.content.decode("utf-8"))

    def test_endpoint_change_product(self):
        r = self.client.post(reverse('endpoint-list'), {
            "product": 1,
            "host": "product1"
        }, format='json')
        eid = r.json()['id']
        self.assertEqual(r.status_code, 201, r.content[:1000])

        r = self.client.patch(reverse('endpoint-detail', args=(eid,)), {
            "product": 2
        }, format='json')
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertIn("Change of product is not possible", r.content.decode("utf-8"))

    def test_endpoint_remove_host(self):
        payload = {
            "product": 1,
            "host": "host1"
        }
        r = self.client.post(reverse('endpoint-list'), payload, format='json')
        eid = r.json()['id']
        self.assertEqual(r.status_code, 201, r.content[:1000])
        r = self.client.patch(reverse('endpoint-detail', args=(eid,)), {
            "host": None
        }, format='json')
        self.assertEqual(r.status_code, 400, r.content[:1000])
        self.assertIn("Host must not be empty", r.content.decode("utf-8"))
