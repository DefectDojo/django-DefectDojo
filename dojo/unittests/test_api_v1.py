import random
from unittest import skip

from django.contrib.auth.models import User
from django.test import TestCase
from tastypie.models import ApiKey
from tastypie.test import ResourceTestCaseMixin

from dojo.models import Product, Engagement, Product_Type


class ApiBasicOperationsTest(ResourceTestCaseMixin, TestCase):
    def setUp(self):
        super(ApiBasicOperationsTest, self).setUp()
        self.username = 'test_user'
        self.password = 'p4ss'
        self.user = User.objects.create_user(self.username, 'user@mail.com',
                                             self.password, is_active=True,
                                             is_staff=True, is_superuser=True)
        self.api_key = ApiKey.objects.create(user=self.user)

        self.prod_type = Product_Type.objects.create(name='WebApp')

    def get_credentials(self):
        return self.create_apikey(self.username, self.user.api_key.key)

    def prepare_a_product(self):
        name = "Product %s" % str(random.randint(0, 999))
        description = "A precise product description"
        return Product.objects.create(name=name, description=description,
                                      prod_type=self.prod_type)

    def test_unauthenticated_request(self):
        """
        An unauthenticated request should return an HTTP Unauthorized (401)
        code.
        """
        r = self.api_client.get('/api/v1/products/')
        self.assertHttpUnauthorized(r)

    def test_list_products(self):
        p = self.prepare_a_product()
        r = self.api_client.get('/api/v1/products/',
                                authentication=self.get_credentials())
        self.assertValidJSONResponse(r)
        data = self.deserialize(r)
        self.assertEqual(1, len(data['objects']))
        self.assertEqual('/api/v1/products/%s/' % p.id,
                         data['objects'][0]['resource_uri'])
        self.assertEqual(p.id, data['objects'][0]['id'])

    def test_get_product_detail(self):
        p = self.prepare_a_product()
        r = self.api_client.get('/api/v1/products/%s/' % p.id,
                                authentication=self.get_credentials())
        self.assertValidJSONResponse(r)
        data = self.deserialize(r)
        self.assertEqual(p.id, data['id'])

    def test_create_product(self):
        p_data = {
            'name': 'Fantastic Product',
            'description': 'Our most recent fantastic product',
            'prod_type': self.prod_type.id,
        }
        r = self.api_client.post('/api/v1/products/',
                                 data=p_data,
                                 authentication=self.get_credentials())
        self.assertHttpCreated(r)
        created_uri = r['Location']
        obj_id = created_uri.split('/')[-2]
        p = Product.objects.get(id=obj_id)
        self.assertEqual('Fantastic Product', p.name)

    @skip("TODO: Test for product updating")
    def test_update_product(self):
        pass

    @skip("TODO: Test for product deletion")
    def test_delete_product(self):
        pass

    def test_create_engagement(self):
        """
        Test for engagement creation, because it takes at least one reference
        to another model.
        """
        p = self.prepare_a_product()
        product_uri = '/api/v1/products/%s/' % str(p.id)
        user_uri = '/api/v1/users/%s/' % str(self.user.id)
        e_data = {
            'product': product_uri,
            'lead': user_uri,
            'status': "In Progress",
            'target_start': '2018-01-01',
            'target_end': '2025-12-31',
        }
        r = self.api_client.post('/api/v1/engagements/',
                                 data=e_data,
                                 authentication=self.get_credentials())
        self.assertHttpCreated(r)

        # Verify the object's creation
        e = Engagement.objects.first()
        self.assertEqual('2018-01-01', e.target_start.strftime('%Y-%m-%d'))
        self.assertEqual('2025-12-31', e.target_end.strftime('%Y-%m-%d'))

    def test_inclomplete_creation_request(self):
        """
        Demonstrate what happens, if not all required fields are provided in a
        creation request.
        """
        p = self.prepare_a_product()
        product_uri = '/api/v1/products/%s/' % str(p.id)
        user_uri = '/api/v1/users/%s/' % str(self.user.id)
        e_data = {
            'product': product_uri,
            'lead': user_uri,
        }
        r = self.api_client.post('/api/v1/engagements/',
                                 data=e_data,
                                 authentication=self.get_credentials())
        self.assertHttpBadRequest(r)
        data = self.deserialize(r)
        self.assertEqual(data, {
            u'engagements': {u'status': [u'This field is required.'],
                             u'target_end': [u'This field is required.'],
                             u'target_start': [u'This field is required.']}})
