from vcr_unittest import VCRTestCase
from dojo.models import User, Endpoint, Notes, Finding, Endpoint_Status, Test, JIRA_Issue
from dojo.models import System_Settings, Engagement
from django.urls import reverse
from rest_framework.test import APITestCase
import json
from django.test import TestCase
from itertools import chain
from dojo.jira_link import helper as jira_helper
import logging
import pprint
import copy

logger = logging.getLogger(__name__)


class DojoTestUtilsMixin(object):

    def get_test_admin(self, *args, **kwargs):
        return User.objects.get(username='admin')

    def system_settings(self, enable_jira=False, enable_jira_web_hook=False, disable_jira_webhook_secret=False, jira_webhook_secret=None):
        ss = System_Settings.objects.get()
        ss.enable_jira = enable_jira
        ss.enable_jira_web_hook = enable_jira_web_hook
        ss.disable_jira_webhook_secret = disable_jira_webhook_secret
        ss.jira_webhook_secret = jira_webhook_secret
        ss.save()

    def create_product(self, name, *args, description='dummy description', prod_type=None, **kwargs):
        if not prod_type:
            prod_type = Product_Type.objects.first()
        product = Product(name=name, description=description, prod_type=prod_type)
        product.save()

    def create_engagement(self, name, product, *args, description=None, **kwargs):
        engagement = Engagement(name=name, description=description, product=product)
        engagement.save()

    def get_test(self, id):
        return Test.objects.get(id=id)

    def get_engagement(self, id):
        return Engagement.objects.get(id=id)

    def assert_jira_issue_count_in_test(self, test_id, count):
        test = self.get_test(test_id)
        jira_issues = JIRA_Issue.objects.filter(finding__in=test.finding_set.all())
        self.assertEqual(count, len(jira_issues))

    def model_to_dict(self, instance):
        opts = instance._meta
        data = {}
        for f in chain(opts.concrete_fields, opts.private_fields):
            data[f.name] = f.value_from_object(instance)
        for f in opts.many_to_many:
            data[f.name] = [i.id for i in f.value_from_object(instance)]
        return data

    def log_model_instance(self, instance):
        logger.debug(pprint.pprint(self.model_to_dict(instance)))

    def log_model_instances(self, instances):
        for instance in instances:
            self.log_model_instance(instance)

    def db_finding_count(self):
        return Finding.objects.all().count()

    def db_endpoint_count(self):
        return Endpoint.objects.all().count()

    def db_endpoint_status_count(self, mitigated=None):
        eps = Endpoint_Status.objects.all()
        if mitigated is not None:
            eps = eps.filter(mitigated=mitigated)
        return eps.count()

    def db_notes_count(self):
        return Notes.objects.all().count()

    def set_jira_push_all_issues(self, engagement_or_product):
        jira_project = jira_helper.get_jira_project(engagement_or_product)
        jira_project.push_all_issues = True
        jira_project.save()


class DojoTestCase(TestCase, DojoTestUtilsMixin):

    def __init__(self, *args, **kwargs):
        TestCase.__init__(self, *args, **kwargs)


class DojoAPITestCase(APITestCase, DojoTestUtilsMixin):

    def __init__(self, *args, **kwargs):
        APITestCase.__init__(self, *args, **kwargs)

    def import_scan(self, payload):
        # logger.debug('import_scan payload %s', payload)
        response = self.client.post(reverse('importscan-list'), payload)
        self.assertEqual(201, response.status_code)
        return json.loads(response.content)

    def reimport_scan(self, payload):
        response = self.client.post(reverse('reimportscan-list'), payload)
        self.assertEqual(201, response.status_code)
        return json.loads(response.content)

    def get_test_api(self, test_id):
        response = self.client.get(reverse('test-list') + '%s/' % test_id, format='json')
        self.assertEqual(200, response.status_code)
        # print('test.content: ', response.content)
        return json.loads(response.content)

    def import_scan_with_params(self, filename, engagement=1, minimum_severity='Low', active=True, verified=True, push_to_jira=None):
        payload = {
                "scan_date": '2020-06-04',
                "minimum_severity": minimum_severity,
                "active": active,
                "verified": verified,
                "scan_type": 'ZAP Scan',
                "file": open(filename),
                "engagement": engagement,
                "version": "1.0.1",
        }

        if push_to_jira is not None:
            payload['push_to_jira'] = push_to_jira

        return self.import_scan(payload)

    def reimport_scan_with_params(self, test_id, filename, engagement=1, minimum_severity='Low', active=True, verified=True, push_to_jira=None):
        payload = {
                "test": test_id,
                "scan_date": '2020-06-04',
                "minimum_severity": minimum_severity,
                "active": active,
                "verified": verified,
                "scan_type": 'ZAP Scan',
                "file": open(filename),
                "engagement": engagement,
                "version": "1.0.1",
        }

        if push_to_jira is not None:
            payload['push_to_jira'] = push_to_jira

        return self.reimport_scan(payload)

    def get_finding_api(self, finding_id):
        response = self.client.get(reverse('finding-list') + '%s/' % finding_id, format='json')
        self.assertEqual(200, response.status_code)
        return response.data

    def post_new_finding_api(self, finding_details, push_to_jira=None):
        payload = copy.deepcopy(finding_details)
        if push_to_jira is not None:
            payload['push_to_jira'] = push_to_jira

        # logger.debug('posting new finding push_to_jira: %s', payload.get('push_to_jira', None))

        response = self.client.post(reverse('finding-list'), payload, format='json')
        self.assertEqual(201, response.status_code)
        return response.data

    def put_finding_api(self, finding_id, finding_details, push_to_jira=None):
        payload = copy.deepcopy(finding_details)
        if push_to_jira is not None:
            payload['push_to_jira'] = push_to_jira

        response = self.client.put(reverse('finding-list') + '%s/' % finding_id, payload, format='json')
        self.assertEqual(200, response.status_code)
        return response.data

    def patch_finding_api(self, finding_id, finding_details, push_to_jira=None):
        payload = copy.deepcopy(finding_details)
        if push_to_jira is not None:
            payload['push_to_jira'] = push_to_jira

        response = self.client.patch(reverse('finding-list') + '%s/' % finding_id, payload, format='json')
        self.assertEqual(200, response.status_code)
        return response.data

    def assert_finding_count_json(self, count, findings_content_json):
        self.assertEqual(findings_content_json['count'], count)

    def get_test_findings_api(self, test_id, active=None, verified=None):
        payload = {'test': test_id}
        if active is not None:
            payload['active'] = active
        if verified is not None:
            payload['verified'] = verified

        response = self.client.get(reverse('finding-list'), payload, format='json')
        self.assertEqual(200, response.status_code)
        # print('findings.content: ', response.content)
        return json.loads(response.content)

    def log_finding_summary_json_api(self, findings_content_json=None):
        # print('summary')
        # print(findings_content_json)
        # print(findings_content_json['count'])

        if not findings_content_json or findings_content_json['count'] == 0:
            logger.debug('no findings')
        else:
            for finding in findings_content_json['results']:
                logger.debug(str(finding['id']) + ': ' + finding['title'][:5] + ':' + finding['severity'] + ': active: ' + str(finding['active']) + ': verified: ' + str(finding['verified']) +
                        ': is_Mitigated: ' + str(finding['is_Mitigated']) + ": notes: " + str([n['id'] for n in finding['notes']]) +
                        ": endpoints: " + str(finding['endpoints']))

        logger.debug('endpoints')
        for ep in Endpoint.objects.all():
            logger.debug(str(ep.id) + ': ' + str(ep))

        logger.debug('endpoint statuses')
        for eps in Endpoint_Status.objects.all():
            logger.debug(str(eps.id) + ': ' + str(eps.endpoint) + ': ' + str(eps.endpoint.id) + ': ' + str(eps.mitigated))


class DojoVCRAPITestCase(DojoAPITestCase, VCRTestCase):
    def __init__(self, *args, **kwargs):
        DojoAPITestCase.__init__(self, *args, **kwargs)
        VCRTestCase.__init__(self, *args, **kwargs)
