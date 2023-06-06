import datetime

from rest_framework.authtoken.models import Token
from rest_framework.reverse import reverse
from rest_framework.test import APITestCase, APIClient

from dojo.models import Product_Type, Product, Engagement, Product_Type_Member, Test, Finding, User, Test_Type, Role, Vulnerability_Id
from dojo.authorization.roles_permissions import Roles


class TestBulkRiskAcceptanceApi(APITestCase):

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create(username='molly', first_name='Molly', last_name='Mocket', is_staff=True)
        cls.token = Token.objects.create(user=cls.user)
        cls.product_type = Product_Type.objects.create(name='Web App')
        cls.product = Product.objects.create(prod_type=cls.product_type, name='Flopper', description='Test product')
        Product_Type_Member.objects.create(product_type=cls.product_type, user=cls.user, role=Role.objects.get(id=Roles.Owner))
        cls.product_2 = Product.objects.create(prod_type=cls.product_type, name='Flopper2', description='Test product2')
        cls.engagement = Engagement.objects.create(product=cls.product, target_start=datetime.date(2000, 1, 1),
                                                   target_end=datetime.date(2000, 2, 1))
        cls.engagement_2a = Engagement.objects.create(product=cls.product_2, target_start=datetime.date(2000, 1, 1),
                                                   target_end=datetime.date(2000, 2, 1))
        cls.engagement_2b = Engagement.objects.create(product=cls.product_2, target_start=datetime.date(2000, 1, 1),
                                                   target_end=datetime.date(2000, 2, 1))

        cls.test_type = Test_Type.objects.create(name='Risk Acceptance Mock Scan', static_tool=True)
        cls.test_a = Test.objects.create(engagement=cls.engagement, test_type=cls.test_type,
                                         target_start=datetime.date(2000, 1, 1), target_end=datetime.date(2000, 2, 1))
        cls.test_b = Test.objects.create(engagement=cls.engagement, test_type=cls.test_type,
                                         target_start=datetime.date(2000, 1, 1), target_end=datetime.date(2000, 2, 1))
        cls.test_c = Test.objects.create(engagement=cls.engagement, test_type=cls.test_type,
                                         target_start=datetime.date(2000, 1, 1), target_end=datetime.date(2000, 2, 1))

        cls.test_d = Test.objects.create(engagement=cls.engagement_2a, test_type=cls.test_type,
                                         target_start=datetime.date(2000, 1, 1), target_end=datetime.date(2000, 2, 1))
        cls.test_e = Test.objects.create(engagement=cls.engagement_2b, test_type=cls.test_type,
                                         target_start=datetime.date(2000, 1, 1), target_end=datetime.date(2000, 2, 1))

        def create_finding(test: Test, reporter: User, cve: str) -> Finding:
            return Finding(test=test, title='Finding {}'.format(cve), cve=cve, severity='High', verified=True,
                           description='Hello world!', mitigation='Delete system32', impact='Everything',
                           reporter=reporter, numerical_severity='S1', static_finding=True, dynamic_finding=False)

        Finding.objects.bulk_create(
            map(lambda i: create_finding(cls.test_a, cls.user, 'CVE-1999-{}'.format(i)), range(50, 150, 3)))
        for finding in Finding.objects.filter(test=cls.test_a):
            Vulnerability_Id.objects.get_or_create(finding=finding, vulnerability_id=finding.cve)
        Finding.objects.bulk_create(
            map(lambda i: create_finding(cls.test_b, cls.user, 'CVE-1999-{}'.format(i)), range(51, 150, 3)))
        for finding in Finding.objects.filter(test=cls.test_b):
            Vulnerability_Id.objects.get_or_create(finding=finding, vulnerability_id=finding.cve)
        Finding.objects.bulk_create(
            map(lambda i: create_finding(cls.test_c, cls.user, 'CVE-1999-{}'.format(i)), range(52, 150, 3)))
        for finding in Finding.objects.filter(test=cls.test_c):
            Vulnerability_Id.objects.get_or_create(finding=finding, vulnerability_id=finding.cve)

        Finding.objects.bulk_create(
            map(lambda i: create_finding(cls.test_d, cls.user, 'CVE-2000-{}'.format(i)), range(50, 150, 3)))
        for finding in Finding.objects.filter(test=cls.test_d):
            Vulnerability_Id.objects.get_or_create(finding=finding, vulnerability_id=finding.cve)
        Finding.objects.bulk_create(
            map(lambda i: create_finding(cls.test_e, cls.user, 'CVE-1999-{}'.format(i)), range(50, 150, 3)))
        for finding in Finding.objects.filter(test=cls.test_e):
            Vulnerability_Id.objects.get_or_create(finding=finding, vulnerability_id=finding.cve)

    def setUp(self) -> None:
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token.key)

    def test_test_accept_risks(self):
        accepted_risks = [{'vulnerability_id': 'CVE-1999-{}'.format(i), 'justification': 'Demonstration purposes',
                           'accepted_by': 'King of the Internet'} for i in range(100, 150)]
        result = self.client.post(reverse('test-accept-risks', kwargs={'pk': self.test_a.id}), data=accepted_risks,
                                  format='json')
        self.assertEqual(len(result.json()), 17)
        self.assertEqual(self.test_a.unaccepted_open_findings.count(), 17)
        self.assertEqual(self.test_b.unaccepted_open_findings.count(), 33)
        self.assertEqual(self.test_c.unaccepted_open_findings.count(), 33)

        self.assertEqual(self.test_d.unaccepted_open_findings.count(), 34)
        self.assertEqual(self.engagement_2a.risk_acceptance.count(), 0)

    def test_engagement_accept_risks(self):
        accepted_risks = [{'vulnerability_id': 'CVE-1999-{}'.format(i), 'justification': 'Demonstration purposes',
                           'accepted_by': 'King of the Internet'} for i in range(100, 150)]
        result = self.client.post(reverse('engagement-accept-risks', kwargs={'pk': self.engagement.id}),
                                  data=accepted_risks, format='json')
        self.assertEqual(len(result.json()), 50)
        self.assertEqual(self.engagement.unaccepted_open_findings.count(), 50)

        self.assertEqual(self.engagement_2a.risk_acceptance.count(), 0)
        self.assertEqual(self.engagement_2a.unaccepted_open_findings.count(), 34)

    def test_finding_accept_risks(self):
        accepted_risks = [{'vulnerability_id': 'CVE-1999-{}'.format(i), 'justification': 'Demonstration purposes',
                           'accepted_by': 'King of the Internet'} for i in range(60, 140)]
        result = self.client.post(reverse('finding-accept-risks'), data=accepted_risks, format='json')
        self.assertEqual(len(result.json()), 106)
        self.assertEqual(Finding.unaccepted_open_findings().count(), 62)

        self.assertEqual(self.engagement_2a.risk_acceptance.count(), 0)
        self.assertEqual(self.engagement_2a.unaccepted_open_findings.count(), 34)

        for ra in self.engagement_2b.risk_acceptance.all():
            for finding in ra.accepted_findings.all():
                self.assertEqual(self.engagement_2a.product, finding.test.engagement.product)
