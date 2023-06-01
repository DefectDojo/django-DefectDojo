import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dojo.settings.settings')
import django
django.setup()

import unittest
from django.test import RequestFactory
from dojo.models import Product, Engagement, Test, Finding, Product_Type, SLA_Configuration, Test_Type, User
from dojo.authorization.roles_permissions import Permissions
from dojo.finding.views import *
from django.utils import timezone

class ViewsTestCase(unittest.TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user, _ = User.objects.get_or_create(username="Test user")

    def test_get_filtered_findings(self):
        prod_type, _ = Product_Type.objects.get_or_create(name="product_type")
        sla_conf, _ = SLA_Configuration.objects.get_or_create(name="SLA Configuration")
        Product.objects.filter(name="ProductTestGithub").delete()
        product, _ = Product.objects.get_or_create(
            name="ProductTestGithub",
            prod_type=prod_type,
            sla_configuration=sla_conf
        )

        engagement = Engagement.objects.create(product=product, target_start=timezone.now(), target_end=timezone.now())
        test_type, _ = Test_Type.objects.get_or_create(name="Test type")
        test = Test.objects.create(engagement=engagement, test_type=test_type, target_start=timezone.now(), target_end=timezone.now())

        request = self.factory.get('/get-filtered-findings')
        request.user = self.user
        request.session = {}

        filtered_findings = get_filtered_findings(request, tid=test.id ,filter_name='Open')

        filtered_findings = get_filtered_findings(request, filter_name='Verified')

        filtered_findings = get_filtered_findings(request, filter_name='Out of Scope')

        filtered_findings = get_filtered_findings(request, filter_name='False Positive')

        filtered_findings = get_filtered_findings(request, filter_name='Inactive')

        filtered_findings = get_filtered_findings(request, filter_name='Accepted')

        filtered_findings = get_filtered_findings(request, filter_name='Closed')

    
    
    def test_open_findings(self):
        request = self.factory.get('/open-findings')
        request.session = {}
        request.user = self.user
        response = open_findings(request)
        self.assertEqual(response.status_code, 200)

    def test_verified_findings(self):
        request = self.factory.get('/verified-findings')
        request.session = {}
        request.user = self.user
        response = verified_findings(request)
        self.assertEqual(response.status_code, 200)

    def test_out_of_scope_findings(self):
        request = self.factory.get('/out-of-scope-findings')
        request.session = {}
        request.user = self.user
        response = out_of_scope_findings(request)
        self.assertEqual(response.status_code, 200)

    def test_inactive_findings(self):
        request = self.factory.get('/inactive_findings')
        request.session = {}
        request.user = self.user
        response = inactive_findings(request)
        self.assertEqual(response.status_code, 200)

    def test_false_positive_findings(self):
        request = self.factory.get('/false_positive_findings')
        request.session = {}
        request.user = self.user
        response = false_positive_findings(request)
        self.assertEqual(response.status_code, 200)

    def test_accepted_findings(self):
        request = self.factory.get('/accepted_findings')
        request.session = {}
        request.user = self.user
        response = accepted_findings(request)
        self.assertEqual(response.status_code, 200)

    def test_closed_findings(self):
        request = self.factory.get('/closed_findings')
        request.session = {}
        request.user = self.user
        response = closed_findings(request)
        self.assertEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main()
