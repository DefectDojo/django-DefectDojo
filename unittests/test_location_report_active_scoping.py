"""
The vulnerable-endpoint report selectors look at the caller's own finding references.

A Location is shared by every product that recorded it. A host that is mitigated in the
caller's product but still active in another product must not appear in the caller's
"vulnerable endpoints" report, since that would tell them about the other product.
"""
from django.test import Client
from django.urls import reverse
from django.utils.timezone import now

from dojo.location.status import FindingLocationStatus
from dojo.models import Dojo_User, Engagement, Finding, Product, Product_Type, Test, Test_Type
from dojo.url.models import URL
from unittests.dojo_test_case import DojoTestCase, skip_unless_v3

SHARED_HOST = "activescope-shared.example.test"
OWN_HOST = "activescope-own.example.test"


@skip_unless_v3
class LocationReportActiveScopingTest(DojoTestCase):
    @classmethod
    def setUpTestData(cls):
        prod_type, _ = Product_Type.objects.get_or_create(name="ActiveScope PT")
        test_type, _ = Test_Type.objects.get_or_create(name="ActiveScope Scan")
        cls.admin = Dojo_User.objects.create(username="activescope_admin", is_active=True, is_superuser=True)

        def product(name):
            return Product.objects.create(name=name, description=name, prod_type=prod_type)

        def finding(product):
            engagement = Engagement.objects.create(product=product, name=f"{product.name} eng", target_start=now().date(), target_end=now().date())
            test = Test.objects.create(engagement=engagement, test_type=test_type, target_start=now(), target_end=now())
            return Finding.objects.create(
                test=test, title=f"{product.name} finding", severity="High", numerical_severity="S1",
                active=True, verified=True, description="body", reporter=cls.admin,
            )

        cls.mine = product("ActiveScope Mine")
        cls.theirs = product("ActiveScope Theirs")
        cls.alice = Dojo_User.objects.create(username="activescope_alice", is_active=True)
        cls.mine.authorized_users.add(cls.alice)

        my_finding = finding(cls.mine)
        their_finding = finding(cls.theirs)

        # Shared host: mitigated for my finding, still active for theirs.
        shared = URL.get_or_create_from_values(protocol="https", host=SHARED_HOST, path="x").location
        shared.associate_with_product(cls.mine)
        shared.associate_with_product(cls.theirs)
        shared.associate_with_finding(my_finding, status=FindingLocationStatus.Mitigated, audit_time=now())
        shared.associate_with_finding(their_finding, audit_time=now())

        # My own host with an active finding.
        own = URL.get_or_create_from_values(protocol="https", host=OWN_HOST, path="x").location
        own.associate_with_product(cls.mine)
        own.associate_with_finding(my_finding, audit_time=now())

    def _get(self, user, name, *args):
        client = Client()
        client.force_login(user)
        response = client.get(reverse(name, args=args))
        self.assertEqual(200, response.status_code)
        return response.content.decode()

    def test_product_endpoint_report_lists_only_hosts_active_in_the_product(self):
        body = self._get(self.alice, "product_endpoint_report", self.mine.id)
        self.assertIn(OWN_HOST, body)
        self.assertNotIn(SHARED_HOST, body)

    def test_endpoint_report_lists_only_hosts_active_for_the_user(self):
        body = self._get(self.alice, "report_endpoints")
        self.assertIn(OWN_HOST, body)
        self.assertNotIn(SHARED_HOST, body)

    def test_superuser_still_sees_the_host_active_elsewhere(self):
        body = self._get(self.admin, "report_endpoints")
        self.assertIn(SHARED_HOST, body)
