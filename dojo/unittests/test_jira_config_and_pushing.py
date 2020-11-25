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

    def add_jira_project_for_product(self, product):
        response = self.client.get(reverse('edit_product', args=(product.id, )))

        product_data = {
            'name': product.name,
            'description': product.description,
            'prod_type': product.prod_type.id,
            'project_key': 'IFFF',
            'jira_instance': 2,
            'enable_engagement_epic_mapping': 'on',
            'push_notes': 'on',
            'product_jira_sla_notification': 'on'
        }

        response = self.client.post(reverse('edit_product', args=(product.id, )), urlencode(product_data), content_type='application/x-www-form-urlencoded')
        self.log_model_instance(product)
        self.log_model_instances(JIRA_Project.objects.all())
        # logger.debug(response.content)
        self.assertRedirects(response, '/product/%i' % product.id)
        return response

    def test_add_jira_instance_unknown_host(self):
        data = self.data_jira_instance
        data['url'] = 'https://jira.hj23412341hj234123421341234ljl.nl'

        # self.client.force_login('admin', backend='django.contrib.auth.backends.ModelBackend')
        # Client.raise_request_exception = False  # needs Django 3.0
        with self.assertRaises(requests.exceptions.RequestException):
            response = self.client.post(reverse('add_jira'), urlencode(data), content_type='application/x-www-form-urlencoded')

    def test_add_jira_instance(self):
        response, jira_instance = self.add_jira_instance(self.data_jira_instance)

    @patch('dojo.jira_link.views.jira_helper.get_jira_connection_raw')
    def test_add_jira_project_to_product(self, jira_mock):
        # TODO: add product also via API, but let's focus on JIRA here
        response = self.add_jira_project_for_product(Product.objects.get(id=1))

# TODO UI
# linking / unlinking
