from django.urls import reverse
from django.utils.timezone import now
from rest_framework.test import APIClient

from dojo.authorization.roles_permissions import Roles
from dojo.filters import ApiFindingFilter
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Product,
    Product_Member,
    Product_Type,
    Role,
    Test,
    Test_Type,
)

from .dojo_test_case import DojoTestCase


class TestApiFindingRelationFilters(DojoTestCase):

    """
    Regression: ?engagement=<id> on /api/v2/findings/ was not a declared filter. A Finding has no
    engagement field, so django-filter dropped the parameter without an error and the list answered
    with every finding the caller could see. engagement, product and prod_type are now short names
    for the test__engagement, test__engagement__product and test__engagement__product__prod_type
    filters.
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User.objects.create(username="rel_filter_user", is_staff=True, is_superuser=True)
        cls.test_type = Test_Type.objects.create(name="Relation Filter Test Type")
        cls.type_a = Product_Type.objects.create(name="Relation Filter PT A")
        cls.type_b = Product_Type.objects.create(name="Relation Filter PT B")
        cls.product_a = Product.objects.create(name="Relation Filter A", prod_type=cls.type_a, description="a")
        cls.product_b = Product.objects.create(name="Relation Filter B", prod_type=cls.type_b, description="b")
        cls.findings = {}
        # Two engagements on product A, so engagement and product answer different sets.
        for key, product, severities in (
            ("a1", cls.product_a, ["High", "High", "Low"]),
            ("a2", cls.product_a, ["High", "Medium"]),
            ("b", cls.product_b, ["High", "Critical", "Low", "Info"]),
        ):
            engagement = Engagement.objects.create(
                name=f"Relation Filter {key}", product=product, target_start=now(), target_end=now(),
            )
            setattr(cls, f"eng_{key}", engagement)
            test = Test.objects.create(
                engagement=engagement, test_type=cls.test_type, target_start=now(), target_end=now(),
            )
            cls.findings[key] = {
                Finding.objects.create(
                    title=f"Relation Filter {key} {index}", test=test, reporter=cls.user, severity=severity,
                ).id
                for index, severity in enumerate(severities)
            }
        cls.scope = Finding.objects.filter(test__engagement__product__in=[cls.product_a, cls.product_b])

    def _filtered(self, data):
        filterset = ApiFindingFilter(data=data, queryset=self.scope)
        self.assertTrue(filterset.is_valid(), msg=filterset.errors)
        return set(filterset.qs.values_list("id", flat=True))

    def test_short_names_are_declared_on_the_long_form_fields(self):
        for alias, field_name in (
            ("engagement", "test__engagement"),
            ("product", "test__engagement__product"),
            ("prod_type", "test__engagement__product__prod_type"),
        ):
            with self.subTest(alias=alias):
                declared = ApiFindingFilter.base_filters.get(alias)
                self.assertIsNotNone(declared, msg=f"{alias} is not declared, so django-filter drops it")
                self.assertEqual(declared.field_name, field_name)
                self.assertEqual(declared.lookup_expr, "in")

    def test_engagement(self):
        self.assertEqual(self._filtered({"engagement": str(self.eng_a1.id)}), self.findings["a1"])
        self.assertEqual(
            self._filtered({"engagement": f"{self.eng_a1.id},{self.eng_b.id}"}),
            self.findings["a1"] | self.findings["b"],
        )

    def test_product(self):
        self.assertEqual(
            self._filtered({"product": str(self.product_a.id)}), self.findings["a1"] | self.findings["a2"],
        )

    def test_prod_type(self):
        self.assertEqual(self._filtered({"prod_type": str(self.type_b.id)}), self.findings["b"])

    def test_short_names_match_the_long_forms(self):
        for alias, long_form, value in (
            ("engagement", "test__engagement", self.eng_a2.id),
            ("product", "test__engagement__product", self.product_b.id),
            ("prod_type", "test__engagement__product__prod_type", self.type_a.id),
        ):
            with self.subTest(alias=alias):
                self.assertEqual(self._filtered({alias: str(value)}), self._filtered({long_form: str(value)}))

    def test_combines_with_other_filters(self):
        high_a1 = set(self.scope.filter(id__in=self.findings["a1"], severity="High").values_list("id", flat=True))
        self.assertEqual(self._filtered({"engagement": str(self.eng_a1.id), "severity": "High"}), high_a1)
        self.assertEqual(self._filtered({"engagement": str(self.eng_b.id), "product": str(self.product_a.id)}), set())

    def test_non_numeric_value_is_invalid(self):
        filterset = ApiFindingFilter(data={"engagement": "abc"}, queryset=self.scope)
        self.assertFalse(filterset.is_valid())
        self.assertIn("engagement", filterset.errors)

    def test_api_list_is_scoped_and_counted(self):
        client = APIClient()
        client.force_authenticate(user=self.user)
        url = reverse("finding-list")
        page1 = client.get(url, {"engagement": self.eng_b.id, "limit": 3}, secure=True)
        page2 = client.get(url, {"engagement": self.eng_b.id, "limit": 3, "offset": 3}, secure=True)
        self.assertEqual(page1.status_code, 200, page1.content[:500])
        self.assertEqual(page1.data["count"], 4)
        self.assertEqual(page2.data["count"], 4)
        self.assertIsNone(page2.data["next"])
        ids = {f["id"] for f in page1.data["results"]} | {f["id"] for f in page2.data["results"]}
        self.assertEqual(ids, self.findings["b"])
        # A parameter that is not a filter is still ignored rather than rejected.
        unknown = client.get(url, {"engagement": self.eng_b.id, "not_a_filter": "1", "limit": 100}, secure=True)
        self.assertEqual({f["id"] for f in unknown.data["results"]}, self.findings["b"])

    def test_api_does_not_widen_for_a_member_of_one_product(self):
        # A Reader of product A only. The short names narrow what the caller may already see, so asking for
        # product B's engagement, product or product type is an empty page, while A's own ids still answer.
        reader = Dojo_User.objects.create(username="rel_filter_reader")
        Product_Member.objects.create(user=reader, product=self.product_a, role=Role.objects.get(id=Roles.Reader))
        self.product_a.authorized_users.add(reader)
        client = APIClient()
        client.force_authenticate(user=reader)
        url = reverse("finding-list")
        for params in (
            {"engagement": self.eng_b.id},
            {"product": self.product_b.id},
            {"prod_type": self.type_b.id},
        ):
            with self.subTest(params=params):
                response = client.get(url, {**params, "limit": 100}, secure=True)
                self.assertEqual(response.status_code, 200, response.content[:500])
                self.assertEqual(response.data["count"], 0)
                self.assertEqual(response.data["results"], [])
        own = client.get(url, {"engagement": self.eng_a2.id, "limit": 100}, secure=True)
        self.assertEqual(own.data["count"], len(self.findings["a2"]))
        self.assertEqual({f["id"] for f in own.data["results"]}, self.findings["a2"])
