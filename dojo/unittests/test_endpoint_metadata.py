import sys
sys.path.append('..')
from dojo.models import Product
from dojo.models import System_Settings
from dojo.models import Endpoint
from dojo.endpoint import views
from django.test import TestCase
from django.test.client import RequestFactory
from django.contrib.auth.models import User
from django.contrib.contenttypes.models import ContentType
from custom_field.models import CustomFieldValue, CustomField
from django.contrib.messages.storage.fallback import FallbackStorage
from django.http import HttpResponseRedirect
from django.http import HttpResponse
from django.core.management import call_command


class EndpointMetaDataTestUtil:

    def __init__(self):
        pass

    @staticmethod
    def create_user(is_staff):
        user = User()
        user.is_staff = is_staff
        user.save()
        return user

    @staticmethod
    def create_get_request(user, path):
        rf = RequestFactory()
        get_request = rf.get(path)
        get_request.user = user
        get_request.session = dict()

        return get_request

    @staticmethod
    def create_post_request(user, path, data):
        rf = RequestFactory()
        post_request = rf.post(path, data=data)
        post_request.user = user
        post_request.session = dict()
        messages = FallbackStorage(post_request)
        setattr(post_request, '_messages', messages)

        return post_request

    @staticmethod
    def get_custom_fields(parent):
        ct = ContentType.objects.get_for_model(parent)
        endpoint_cf = CustomField.objects.filter(content_type=ct)
        endpoint_metadata = {}
        for cf in endpoint_cf:
            cfv = CustomFieldValue.objects.filter(field=cf, object_id=parent.id)
            if len(cfv):
                endpoint_metadata[cf.name] = cfv[0].value
        return endpoint_metadata

    @staticmethod
    def save_custom_field(parent, name, value):
        ct = ContentType.objects.get_for_model(parent)
        cf, created = CustomField.objects.get_or_create(name=name,
                                                        content_type=ct,
                                                        field_type='a')
        cf.save()
        cfv, created = CustomFieldValue.objects.get_or_create(field=cf,
                                                              object_id=parent.id)
        cfv.value = value
        cfv.clean()
        cfv.save()

    @staticmethod
    def delete_custom_field(parent, name):
        ct = ContentType.objects.get_for_model(parent)

        cf, created = CustomField.objects.get_or_create(name=name,
                                                        content_type=ct,
                                                        field_type='a')

        cfv, created = CustomFieldValue.objects.get_or_create(field=cf,
                                                              object_id=parent.id)

        cfv.delete()

    @staticmethod
    def get_endpoint_metadata(id):
        endpoint = Endpoint.objects.get(id=id)
        endpoint_metadata = EndpointMetaDataTestUtil.get_custom_fields(endpoint)
        return endpoint_metadata

    @staticmethod
    def get_product_metadata(id):
        product = Product.objects.get(id=id)
        product_metadata = EndpointMetaDataTestUtil.get_custom_fields(product)
        return product_metadata


class TestAddEndpointMetaData(TestCase):

    add_meta_data_url = 'endpoint/1/add_meta_data'

    def setUp(self):
        p = Product()
        p.Name = 'Test Product'
        p.Description = 'Product for Testing Endpoint functionality'
        p.save()

        e = Endpoint()
        e.product = p
        e.host = '127.0.0.1'
        e.save()

        call_command('loaddata', 'dojo/fixtures/system_settings', verbosity=0)

    def make_request(self, user_is_staff, id, data=None):
        user = EndpointMetaDataTestUtil.create_user(user_is_staff)

        if data:
            request = EndpointMetaDataTestUtil.create_post_request(user, self.add_meta_data_url, data)
        else:
            request = EndpointMetaDataTestUtil.create_get_request(user, self.add_meta_data_url)

        v = views.add_meta_data(request, id)

        return v

    def test_unauthorized_add_meta_data_fails(self):
        v = self.make_request(False, 1)
        self.assertIsInstance(v, HttpResponseRedirect)

    def test_add_meta_data_with_illegal_endpoint_fails(self):
        with self.assertRaises(Exception):
            v = self.make_request(True, None)

    def test_add_meta_data_returns_view(self):
        v = self.make_request(True, 1)
        self.assertIsNotNone(v)

    def test_add_meta_data_returns_view_with_endpoint_host(self):
        v = self.make_request(True, 1)
        self.assertContains(v, '127.0.0.1')

    def test_add_meta_data_returns_view_with_form(self):
        v = self.make_request(True, 1)
        self.assertContains(v, '<form')
        self.assertContains(v, '<input type="text" name="name" id="id_name"')
        self.assertContains(v, '<textarea name="value" id="id_value"')

    def test_save_meta_data_form_without_name_and_value(self):
        util = EndpointMetaDataTestUtil()
        request = util.create_post_request(util.create_user(True), self.add_meta_data_url, None)
        v = views.add_meta_data(request, 1)
        self.assertContains(v, 'This field is required.', 2)

    def test_save_meta_data_form_without_name(self):
        v = self.make_request(True, 1, {'value': 'TestValue'})
        self.assertContains(v, 'This field is required.', 1)

    def test_save_meta_data_form_with_name_and_value(self):
        v = self.make_request(True, 1, {'name': 'TestField', 'value': 'TestValue'})
        endpoint_metadata = EndpointMetaDataTestUtil.get_endpoint_metadata(1)

        self.assertEqual(1, len(endpoint_metadata))
        self.assertEqual('TestValue', endpoint_metadata['TestField'])

    def test_add_endpoint_meta_data_has_no_impact_on_product_metadata(self):
        v = self.make_request(True, 1, {'name': 'TestField', 'value': 'TestValue'})
        product_metadata = EndpointMetaDataTestUtil.get_product_metadata(1)
        self.assertEqual(0, len(product_metadata))

    def test_save_meta_data_form_with_illegal_endpoint_fails(self):
        with self.assertRaises(Exception):
            v = self.make_request(True, None, {'name': 'TestField', 'value': 'TestValue'})

    def test_unauthorized_save_meta_data_form_fails(self):
        v = self.make_request(False, 1, {'name': 'TestField', 'value': 'TestValue'})
        endpoint_metadata = EndpointMetaDataTestUtil.get_endpoint_metadata(1)
        self.assertEqual(0, len(endpoint_metadata))


class TestEditEndpointMetaData(TestCase):

    edit_meta_data_url = 'endpoint/1/edit_meta_data'

    def setUp(self):
        p = Product()
        p.Name = 'Test Product'
        p.Description = 'Product for Testing Endpoint functionality'
        p.save()

        e = Endpoint()
        e.product = p
        e.host = '127.0.0.1'
        e.save()

        EndpointMetaDataTestUtil.save_custom_field(e, 'TestField', 'TestValue')
        EndpointMetaDataTestUtil.save_custom_field(p, 'TestProductField', 'TestProductValue')

    def make_request(self, user_is_staff, id, data=None):
        user = EndpointMetaDataTestUtil.create_user(user_is_staff)

        if data:
            request = EndpointMetaDataTestUtil.create_post_request(user, self.edit_meta_data_url, data)
        else:
            request = EndpointMetaDataTestUtil.create_get_request(user, self.edit_meta_data_url)

        v = views.edit_meta_data(request, id)

        return v

    def test_unauthorized_edit_meta_data(self):
        v = self.make_request(False, 1)
        self.assertIsInstance(v, HttpResponse)
        self.assertEqual(302, v.status_code)

    def test_edit_meta_data_with_illegal_endpoint_fails(self):
        with self.assertRaises(Exception):
            v = self.make_request(True, None)

    def test_edit_meta_data_returns_view(self):
        v = self.make_request(True, 1)
        self.assertIsNotNone(v)

    def test_edit_meta_data_returns_view_with_endpoint_host(self):
        v = self.make_request(True, 1)
        self.assertContains(v, '127.0.0.1')

    def test_edit_meta_data_returns_view_with_custom_field_name(self):
        v = self.make_request(True, 1)
        self.assertContains(v, 'TestField')

    def test_edit_meta_data_returns_view_with_custom_field_value(self):
        v = self.make_request(True, 1)
        self.assertContains(v, 'TestValue')

    def test_save_meta_data_with_illegal_endpoint_fails(self):
        with self.assertRaises(Exception):
            v = self.make_request(True, None, {'cfv_1': 'EditedValue'})

    def test_save_meta_data_with_new_value_changes_value(self):
        v = self.make_request(True, 1, {'cfv_1': 'EditedValue'})
        self.assertIsInstance(v, HttpResponseRedirect)

        endpoint_metadata = EndpointMetaDataTestUtil.get_endpoint_metadata(1)

        self.assertEqual(1, len(endpoint_metadata))
        self.assertEqual('EditedValue', endpoint_metadata['TestField'])

    def test_save_endpoint_meta_data_does_not_change_product_metadata(self):
        v = self.make_request(True, 1, {'cfv_1': 'EditedValue'})
        product_metadata = EndpointMetaDataTestUtil.get_product_metadata(1)
        self.assertEqual('TestProductValue', product_metadata['TestProductField'])

    def test_save_meta_data_with_empty_value_deletes_field(self):
        v = self.make_request(True, 1, {'cfv_1': ''})
        endpoint_metadata = EndpointMetaDataTestUtil.get_endpoint_metadata(1)
        self.assertEqual(0, len(endpoint_metadata))

    def test_unauthorized_save_meta_data_changes_fails(self):
        v = self.make_request(False, 1, {'cfv_1': 'EditedValue'})
        self.assertIsInstance(v, HttpResponseRedirect)

        endpoint_metadata = EndpointMetaDataTestUtil.get_endpoint_metadata(1)
        self.assertEqual('TestValue', endpoint_metadata['TestField'])


class TestViewEndpointMetaData(TestCase):

    def setUp(self):
        self.p = Product()
        self.p.Name = 'Test Product'
        self.p.Description = 'Product for Testing Endpoint functionality'
        self.p.save()

        self.e = Endpoint()
        self.e.product = self.p
        self.e.host = '127.0.0.1'
        self.e.save()

        call_command('loaddata', 'dojo/fixtures/system_settings', verbosity=0)
        self.util = EndpointMetaDataTestUtil()
        self.util.save_custom_field(self.e, 'TestField', 'TestValue')

    def test_view_endpoint_without_metadata_has_no_additional_info(self):
        self.util.delete_custom_field(self.e, 'TestField')

        get_request = self.util.create_get_request(self.util.create_user(True), 'endpoint/1')
        v = views.view_endpoint(get_request, 1)

        self.assertNotContains(v, 'Additional Information')

    def test_view_endpoint_with_metadata_has_additional_info(self):
        get_request = self.util.create_get_request(self.util.create_user(True), 'endpoint/1')
        v = views.view_endpoint(get_request, 1)

        self.assertContains(v, "Additional Information")
        self.assertContains(v, 'TestField')
        self.assertContains(v, 'TestValue')
