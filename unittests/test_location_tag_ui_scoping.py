"""
Location tag scoping on the two pages ``test_location_tag_scoping.py`` does not cover.

That suite asserts the REST bodies and filters only, so the classic search page and the
Product Endpoint Report kept rendering and matching the raw shared tag relation. Both read
a Location the caller is authorized for, whose tag set belongs to every product on the row.
"""
from django.test import override_settings
from django.urls import reverse
from django.utils.timezone import now

from dojo.authorization.roles_permissions import Roles
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
    User,
)
from dojo.url.models import URL
from unittests.dojo_test_case import DojoTestCase, skip_unless_v3

SHARED_HOST = "uitagscope-shared.example.test"
OWN_HOST = "uitagscope-own.example.test"

FOREIGN_TAG = "bsecretr7k2q9"
OWN_TAG = "aownlabel"


@skip_unless_v3
@override_settings(WATSON_SEARCH_ENABLED=True)
class LocationTagUIScopingTest(DojoTestCase):
    @classmethod
    def setUpTestData(cls):
        prod_type, _ = Product_Type.objects.get_or_create(name="UITagScope PT")
        test_type, _ = Test_Type.objects.get_or_create(name="UITagScope Scan")

        def product(name):
            return Product.objects.create(name=name, description=name, prod_type=prod_type)

        cls.mine = product("UITagScope Mine")
        cls.theirs = product("UITagScope Theirs")

        cls.alice = User.objects.create_user(
            username="uitagscope_alice",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
        )
        Product_Member.objects.create(
            user=cls.alice, product=cls.mine, role=Role.objects.get(id=Roles.Reader),
        )
        cls.mine.authorized_users.add(Dojo_User.objects.get(pk=cls.alice.pk))

        engagement = Engagement.objects.create(
            product=cls.mine, name="UITagScope eng",
            target_start=now().date(), target_end=now().date(),
        )
        test = Test.objects.create(
            engagement=engagement, test_type=test_type, target_start=now(), target_end=now(),
        )
        finding = Finding.objects.create(
            test=test, title="UITagScope finding", severity="High", numerical_severity="S1",
            active=True, verified=True, description="body", reporter=cls.alice,
        )

        def location(host, tag, *products):
            loc = URL.get_or_create_from_values(protocol="https", host=host, path="x").location
            for prod in products:
                loc.associate_with_product(prod)
            loc.associate_with_finding(finding, audit_time=now())
            loc.tags.set([tag])
            return loc

        # Alice's product references it, so the row is hers to see. The tag came from theirs.
        cls.shared = location(SHARED_HOST, FOREIGN_TAG, cls.mine, cls.theirs)
        cls.own = location(OWN_HOST, OWN_TAG, cls.mine)

    def _search(self, query):
        self.client.force_login(self.alice)
        response = self.client.get(reverse("simple_search"), {"query": query})
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def _report(self):
        """The report options page, which lists the locations the report will cover."""
        self.client.force_login(self.alice)
        response = self.client.get(reverse("product_endpoint_report", args=(self.mine.id,)))
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def test_search_withholds_a_foreign_products_tag(self):
        body = self._search("uitagscope")
        self.assertIn(SHARED_HOST, body)
        self.assertNotIn(FOREIGN_TAG, body)

    def test_search_still_renders_my_own_tag(self):
        self.assertIn(OWN_TAG, self._search("uitagscope"))

    def test_search_tag_operator_does_not_match_a_foreign_tag(self):
        for query in (f"tag:{FOREIGN_TAG}", f"tag:{FOREIGN_TAG[:6]}", f"tags:{FOREIGN_TAG}"):
            self.assertNotIn(SHARED_HOST, self._search(query), query)

    def test_search_tag_operator_still_matches_my_own_tag(self):
        for query in (f"tag:{OWN_TAG}", f"tag:{OWN_TAG[:6]}", f"tags:{OWN_TAG}"):
            body = self._search(query)
            self.assertIn(OWN_HOST, body, query)
            self.assertIn(OWN_TAG, body, query)

    def test_search_negated_tag_operator_treats_a_foreign_tag_set_as_empty(self):
        self.assertIn(SHARED_HOST, self._search(f"not-tag:{FOREIGN_TAG}"))

    def test_product_endpoint_report_withholds_a_foreign_products_tag(self):
        body = self._report()
        self.assertIn(SHARED_HOST, body)
        self.assertNotIn(FOREIGN_TAG, body)

    def test_product_endpoint_report_still_renders_my_own_tag(self):
        self.assertIn(OWN_TAG, self._report())
