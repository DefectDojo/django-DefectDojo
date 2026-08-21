from django.test import override_settings
from django.urls import reverse

from dojo.models import (
    Dojo_User,
    Finding_Template,
    Language_Type,
    Languages,
    Product,
    Product_Type,
    System_Settings,
)
from unittests.dojo_test_case import DojoTestCase


# Every facet on the search page is seeded from a get_authorized_* queryset so that a
# result row can never reference a product the caller is not authorized on. Assert that
# for the language facet, which is the one that had no such seed. The helpers themselves
# are covered by test_authorization_queryset_coverage.py; this covers the view calling them.
#
# V3_FEATURE_LOCATIONS is pinned off to match OSS CI defaults, as in
# test_watson_search_disabled.py.
@override_settings(SECURE_SSL_REDIRECT=False, V3_FEATURE_LOCATIONS=False, WATSON_SEARCH_ENABLED=True)
class TestSimpleSearchProductScoping(DojoTestCase):

    def setUp(self):
        System_Settings.objects.get_or_create(id=1)
        super().setUp()
        product_type = Product_Type.objects.create(name="search-scoping-pt")
        self.my_product = Product.objects.create(
            name="search-scoping-mine", description="mine", prod_type=product_type)
        self.other_product = Product.objects.create(
            name="search-scoping-theirs", description="theirs", prod_type=product_type)
        Languages.objects.create(
            product=self.my_product,
            language=Language_Type.objects.create(language="ScopingLangMine"))
        Languages.objects.create(
            product=self.other_product,
            language=Language_Type.objects.create(language="ScopingLangTheirs"))

        # OSS authorization keys off the legacy authorized_users M2M, and is_staff
        # bypasses it, so the user has to be a plain authorized user to be meaningful.
        self.user = Dojo_User.objects.create(username="search-scoping-member", is_active=True)
        self.my_product.authorized_users.add(self.user)
        self.client.force_login(self.user)

    def test_language_facet_excludes_unauthorized_products(self):
        response = self.client.get(reverse("simple_search"), {"query": "language:ScopingLang"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            {row.product_id for row in response.context["languages"]},
            {self.my_product.id},
        )


@override_settings(SECURE_SSL_REDIRECT=False, V3_FEATURE_LOCATIONS=False, WATSON_SEARCH_ENABLED=True)
class TestSimpleSearchFindingTemplateScoping(DojoTestCase):

    def setUp(self):
        System_Settings.objects.get_or_create(id=1)
        super().setUp()
        self.template = Finding_Template.objects.create(
            title="TemplateScopingTitle", description="TemplateScopingBody")

    def _search(self, user):
        self.client.force_login(user)
        # Operator-only query: no keywords means no watson filter, so this covers the seed.
        return self.client.get(reverse("simple_search"), {"query": "template:any"})

    def test_finding_templates_hidden_without_global_permission(self):
        user = Dojo_User.objects.create(username="template-scoping-nobody", is_active=True)
        response = self._search(user)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["finding_templates"]), [])
        self.assertNotContains(response, "TemplateScopingBody")

    def test_finding_templates_visible_with_global_permission(self):
        user = Dojo_User.objects.create(
            username="template-scoping-staff", is_active=True, is_staff=True)
        response = self._search(user)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [row.id for row in response.context["finding_templates"]], [self.template.id])
