from django.test import Client
from django.urls import reverse
from django.utils.timezone import now

from dojo.models import Dojo_User, Engagement, Product, Product_Type, Test, Test_Type
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


@versioned_fixtures
class TestReportFindingFilterScoping(DojoTestCase):

    fixtures = ["dojo_testdata.json"]

    TITLE_A = "REPORT_FILTER_TEST_A_7c1e"
    TITLE_B = "REPORT_FILTER_TEST_B_4f9d"

    @classmethod
    def setUpTestData(cls):
        test_type, _ = Test_Type.objects.get_or_create(name="Report Filter Scoping Scan")
        tests = []
        for suffix, title in (("A", cls.TITLE_A), ("B", cls.TITLE_B)):
            prod_type = Product_Type.objects.create(name=f"Report Filter Scoping PT {suffix}")
            product = Product.objects.create(name=f"Report Filter Scoping {suffix}", description="x", prod_type=prod_type)
            engagement = Engagement.objects.create(product=product, target_start=now(), target_end=now())
            tests.append(Test.objects.create(engagement=engagement, test_type=test_type, title=title,
                                             target_start=now(), target_end=now()))
        cls.test_a, cls.test_b = tests
        cls.user = Dojo_User.objects.create_user(username="report_filter_scoping", password="not-a-real-secret")  # noqa: S106
        cls.test_a.engagement.product.authorized_users.add(cls.user)

    def test_test_choices_are_limited_to_authorized_tests(self):
        client = Client()
        client.force_login(self.user)
        for url in (
            reverse("report_findings"),
            reverse("report_builder"),
            reverse("test_report", args=(self.test_a.id,)),
        ):
            with self.subTest(url=url):
                response = client.get(url)
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, self.TITLE_A)
                self.assertNotContains(response, self.TITLE_B)
