from django.urls import reverse
from .dojo_test_case import DojoTestCase
from dojo.models import JIRA_Instance, Product, JIRA_Project
from django.utils.http import urlencode
from unittest.mock import patch
import requests
# from unittest import skip
import logging

logger = logging.getLogger(__name__)


class JIRAConfigAndPushTest(DojoTestCase):
    fixtures = ['dojo_testdata.json']

    data_jira_instance = {
            'configuration_name': 'something_jira',
            'url': 'https://127.0.0.1',
            'username': 'defectdojo',
            'password': 'defectdojo-password',
            'default_issue_type': 'Bug',
            'epic_name_id': 1,
            'open_status_key': 1,
            'close_status_key': 1,
            'info_mapping_severity': 'Info',
            'low_mapping_severity': 'Low',
            'medium_mapping_severity': 'Medium',
            'high_mapping_severity': 'High',
            'critical_mapping_severity': 'Critical',
            # finding_text': '',
            'accepted_mapping_resolution': 'Fixed',
            'false_positive_mapping_resolution': 'False Positive',
            # global_jira_sla_notification': '',
    }

    # jira_mock = MagicMock()

    def __init__(self, *args, **kwargs):
        DojoTestCase.__init__(self, *args, **kwargs)

    def setUp(self):
        self.system_settings(enable_jira=True)
        self.client.force_login(self.get_test_admin())

    @patch('dojo.jira_link.views.jira_helper.get_jira_connection_raw')
    def add_jira_instance(self, data, jira_mock):
        response = self.client.post(reverse('add_jira'), urlencode(data), content_type='application/x-www-form-urlencoded')
        # check that storing a new config triggers a login call to JIRA
        jira_mock.assert_called_once_with(data['url'], data['username'], data['password'])
        # succesful, so should redirect to list of JIRA instances
        self.assertRedirects(response, '/jira')

        jira_instance = JIRA_Instance.objects.filter(configuration_name=data['configuration_name'], url=data['url']).last()
        return response, jira_instance

    def test_add_jira_instance(self):
        response, jira_instance = self.add_jira_instance(self.data_jira_instance)

    # no mock so we can assert the exception raised
    def test_add_jira_instance_unknown_host(self):
        data = self.data_jira_instance
        data['url'] = 'https://jira.hj23412341hj234123421341234ljl.nl'

        # self.client.force_login('admin', backend='django.contrib.auth.backends.ModelBackend')
        # Client.raise_request_exception = False  # needs Django 3.0
        with self.assertRaises(requests.exceptions.RequestException):
            response = self.client.post(reverse('add_jira'), urlencode(data), content_type='application/x-www-form-urlencoded')

    def get_jira_project_data(self, product):
        return {
            'name': product.name,
            'description': product.description,
            'prod_type': product.prod_type.id,
            'project_key': 'IFFF',
            'jira_instance': 2,
            'enable_engagement_epic_mapping': 'on',
            'push_notes': 'on',
            'product_jira_sla_notification': 'on'
        }

    def get_jira_project_data2(self, product):
        return {
            'name': product.name,
            'description': product.description,
            'prod_type': product.prod_type.id,
            'project_key': 'IFFF2',
            'jira_instance': 2,
            'enable_engagement_epic_mapping': 'on',
            'push_notes': 'on',
            'product_jira_sla_notification': 'on'
        }

    def get_jira_project_empty_data(self, product):
        return {
            'name': product.name,
            'description': product.description,
            'prod_type': product.prod_type.id,
            # 'project_key': 'IFFF',
            # 'jira_instance': 2,
            # 'enable_engagement_epic_mapping': 'on',
            # 'push_notes': 'on',
            'product_jira_sla_notification': 'on'  # default is true so we have to supply to make has_changed() work OK
        }

    def get_expected_redirect_product(self, product):
        return '/product/%i' % product.id

    def get_expected_redirect_edit_product(self, product):
        return '/product/edit/%i' % product.id

    def edit_product_jira(self, product, data, expect_redirect_to=None, expect_200=False):
        response = self.client.get(reverse('edit_product', args=(product.id, )))

        logger.debug('before: JIRA_Project last')
        self.log_model_instance(JIRA_Project.objects.last())

        response = self.client.post(reverse('edit_product', args=(product.id, )), urlencode(data), content_type='application/x-www-form-urlencoded')
        # self.log_model_instance(product)
        logger.debug('after: JIRA_Project last')
        self.log_model_instance(JIRA_Project.objects.last())

        if expect_200:
            self.assertEqual(response.status_code, 200)
        elif expect_redirect_to:
            self.assertRedirects(response, expect_redirect_to)
        else:
            self.assertEqual(response.status_code, 200)
        return response

    def edit_jira_project_for_product_with_data(self, product, data, expected_delta_jira_project_db=0, expect_redirect_to=None, expect_200=None):
        jira_project_count_before = self.db_jira_project_count()
        print('before: ' + str(jira_project_count_before))

        if not expect_redirect_to and not expect_200:
            expect_redirect_to = self.get_expected_redirect_product(product)

        response = self.edit_product_jira(product, data, expect_redirect_to=expect_redirect_to)

        print('after: ' + str(self.db_jira_project_count()))

        self.assertEqual(self.db_jira_project_count(), jira_project_count_before + expected_delta_jira_project_db)
        return response

    def edit_jira_project_for_product(self, product, expected_delta_jira_project_db=0, expect_redirect_to=None, expect_200=False):
        return self.edit_jira_project_for_product_with_data(product, self.get_jira_project_data(product), expected_delta_jira_project_db, expect_redirect_to=expect_redirect_to, expect_200=expect_200)

    def edit_jira_project_for_product2(self, product, expected_delta_jira_project_db=0, expect_redirect_to=None, expect_200=False):
        return self.edit_jira_project_for_product_with_data(product, self.get_jira_project_data2(product), expected_delta_jira_project_db, expect_redirect_to=expect_redirect_to, expect_200=expect_200)

    def empty_jira_project_for_product(self, product, expected_delta_jira_project_db=0, expect_redirect_to=None, expect_200=False):
        jira_project_count_before = self.db_jira_project_count()
        print('before: ' + str(jira_project_count_before))

        if not expect_redirect_to and not expect_200:
            expect_redirect_to = self.get_expected_redirect_product(product)

        response = self.edit_product_jira(product, self.get_jira_project_empty_data(product), expect_redirect_to=expect_redirect_to, expect_200=expect_200)

        print('after: ' + str(self.db_jira_project_count()))

        self.assertEqual(self.db_jira_project_count(), jira_project_count_before + expected_delta_jira_project_db)
        return response

    @patch('dojo.jira_link.views.jira_helper.is_jira_project_valid')
    def test_add_jira_project_to_product_without_jira_project(self, jira_mock):
        jira_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        # TODO: add product also via API, but let's focus on JIRA here
        response = self.edit_jira_project_for_product(Product.objects.get(id=3), 1)
        self.assertEqual(jira_mock.call_count, 1)

    @patch('dojo.jira_link.views.jira_helper.is_jira_project_valid')
    def test_add_empty_jira_project_to_product_without_jira_project(self, jira_mock):
        jira_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        response = self.empty_jira_project_for_product(Product.objects.get(id=3), 0)
        self.assertEqual(jira_mock.call_count, 0)

    @patch('dojo.jira_link.views.jira_helper.is_jira_project_valid')
    def test_edit_jira_project_to_product_with_jira_project(self, jira_mock):
        jira_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        response = self.edit_jira_project_for_product(Product.objects.get(id=3), 1)
        response = self.edit_jira_project_for_product2(Product.objects.get(id=3), 0)
        self.assertEqual(jira_mock.call_count, 2)

    @patch('dojo.jira_link.views.jira_helper.is_jira_project_valid')
    def test_edit_empty_jira_project_to_product_with_jira_project(self, jira_mock):
        jira_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        response = self.edit_jira_project_for_product(Product.objects.get(id=3), 1)
        # clearing out jira config used to be possible. what todo?
        # - delete jira project? would disconnect all existing jira issues in defect dojo from the config?
        # - allow jira project with empty jira instance and/or empty project_key? unpredictable behaviour
        # - so prevent clearing out these values
        # response = self.empty_jira_project_for_product(Product.objects.get(id=3), -1)
        # errors means it won't redirect to view_product, but returns a 200 and redisplays the edit product page
        response = self.empty_jira_project_for_product(Product.objects.get(id=3), 0, expect_200=True)
        self.assertEqual(jira_mock.call_count, 1)

    @patch('dojo.jira_link.views.jira_helper.is_jira_project_valid')
    def test_add_jira_project_to_product_without_jira_project_invalid_project(self, jira_mock):
        jira_mock.return_value = False  # cannot set return_value in decorated AND have the mock into the method
        # errors means it won't redirect to view_product, but returns a 200 and redisplays the edit product page
        response = self.edit_jira_project_for_product(Product.objects.get(id=3), 0, expect_200=True)
        self.assertEqual(jira_mock.call_count, 1)

    @patch('dojo.jira_link.views.jira_helper.is_jira_project_valid')
    def test_edit_jira_project_to_product_with_jira_project_invalid_project(self, jira_mock):
        jira_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        response = self.edit_jira_project_for_product(Product.objects.get(id=3), 1)
        jira_mock.return_value = False
        response = self.edit_jira_project_for_product2(Product.objects.get(id=3), 0, expect_200=True)
        self.assertEqual(jira_mock.call_count, 2)

    # one test with jira disabled to make sure it doesn't fail in that scenario
    @patch('dojo.jira_link.views.jira_helper.is_jira_project_valid')
    def test_edit_jira_project_to_product_with_jira_project_invalid_project_jira_disabled(self, jira_mock):
        self.system_settings(enable_jira=False)
        jira_mock.return_value = True  # cannot set return_value in decorated AND have the mock into the method
        response = self.edit_jira_project_for_product(Product.objects.get(id=3), 0)
        response = self.edit_jira_project_for_product2(Product.objects.get(id=3), 0)
        self.assertEqual(jira_mock.call_count, 0)

# TODO UI
# linking / unlinking
