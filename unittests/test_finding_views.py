import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dojo.settings.settings')
import django
django.setup()

import unittest
from django.test import RequestFactory
from dojo.models import Product, Engagement, Test, Finding, Product_Type, SLA_Configuration, Test_Type, User
from dojo.authorization.roles_permissions import Permissions
from dojo.finding.views import *
import datetime
from django.utils import timezone

class ViewsTestCase(unittest.TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_get_filtered_findings(self):
        # Crear un producto, un engagement y una prueba para la prueba
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

        user, _ = User.objects.get_or_create(username="User test")

        """# Crear algunos hallazgos para la prueba
        finding1 = Finding.objects.create(test=test, title="Finding 1", severity="High", reporter=user)
        finding2 = Finding.objects.create(test=test, title="Finding 2", severity="Medium", reporter=user)
        finding3 = Finding.objects.create(test=test, title="Finding 3", severity="Low", reporter=user)"""

        # Crear una solicitud GET para la vista
        request = self.factory.get('/get-filtered-findings')
        request.user = user
        request.session = {}

        filtered_findings = get_filtered_findings(request, tid=test.id ,filter_name='Open')
        #self.assertEqual(filtered_findings.qs.count(), 3)

        filtered_findings = get_filtered_findings(request, filter_name='Verified')
        #self.assertEqual(filtered_findings.qs.count(), 2)

        filtered_findings = get_filtered_findings(request, filter_name='Out of Scope')
        #self.assertEqual(filtered_findings.qs.count(), 1)

        filtered_findings = get_filtered_findings(request, filter_name='False Positive')
        #self.assertEqual(filtered_findings.qs.count(), 1)

        filtered_findings = get_filtered_findings(request, filter_name='Inactive')
        #self.assertEqual(filtered_findings.qs.count(), 1)

        filtered_findings = get_filtered_findings(request, filter_name='Accepted')
        #self.assertEqual(filtered_findings.qs.count(), 1)

        filtered_findings = get_filtered_findings(request, filter_name='Closed')
        #self.assertEqual(filtered_findings.qs.count(), 0)


if __name__ == '__main__':
    unittest.main()
