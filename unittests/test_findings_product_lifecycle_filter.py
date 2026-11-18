from django.test import override_settings
from django.utils.timezone import now
from rest_framework.test import APITestCase

from dojo.models import Dojo_User, Engagement, Finding, Product, Product_Lifecycle, Product_Type, Test, Test_Type


@override_settings(SECURE_SSL_REDIRECT=False)
class TestFindingsProductLifecycleFilter(APITestCase):

    """
    Regression: a Lifecycle option's value may contain a comma (``beta, ga``), but ``product_lifecycle``
    split its parameter on every comma, so such an option could never be matched. A value holding a
    comma now travels in double quotes, CSV-style (``"beta, ga",production``); a list without quotes
    splits exactly as before.
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User.objects.create(username="lifecycle_filter_admin", is_staff=True, is_superuser=True)
        prod_type = Product_Type.objects.create(name="Lifecycle Filter PT")
        test_type = Test_Type.objects.create(name="Lifecycle Filter Scan")
        cls.findings = {}
        for value in ("beta, ga", "production", "beta"):
            lifecycle, _ = Product_Lifecycle.objects.get_or_create(value=value, defaults={"name": value})
            product = Product.objects.create(name=f"Lifecycle Filter {value}", description="x", prod_type=prod_type, lifecycle=lifecycle)
            engagement = Engagement.objects.create(name="e", product=product, target_start=now(), target_end=now())
            test = Test.objects.create(engagement=engagement, test_type=test_type, target_start=now(), target_end=now())
            cls.findings[value] = Finding.objects.create(
                title=f"Lifecycle Filter {value}", test=test, severity="High", reporter=cls.user, date=now().date(),
            ).id

    def setUp(self):
        self.client.force_authenticate(user=self.user)

    def _values(self, param):
        response = self.client.get("/api/v2/findings/", {"product_lifecycle": param, "limit": 100})
        self.assertEqual(response.status_code, 200, response.content[:500])
        by_id = {finding_id: value for value, finding_id in self.findings.items()}
        return {by_id[row["id"]] for row in response.json()["results"] if row["id"] in by_id}

    def test_a_quoted_value_with_a_comma_is_one_value(self):
        self.assertEqual(self._values('"beta, ga"'), {"beta, ga"})

    def test_a_quoted_value_sits_in_a_list_with_plain_ones(self):
        self.assertEqual(self._values('"beta, ga",production'), {"beta, ga", "production"})

    def test_a_list_without_quotes_splits_as_before(self):
        self.assertEqual(self._values("production,beta"), {"production", "beta"})
        self.assertEqual(self._values("production"), {"production"})
