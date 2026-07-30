"""
Regression tests for finding scoping in the endpoint and host views
(``dojo/url/ui/views.py`` ``process_endpoint_view``).

A Location row is deduplicated globally and shared by every product that
references it, and a Location is authorized if any one of those products is the
caller's. Authorizing the Location therefore says nothing about whose findings
are attached to it, so the views must scope the findings themselves.

The views are called directly rather than through the test client so the
assertions cover the view and its template, independent of any redirect
middleware layered on top of the route.
"""
from crum import impersonate
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.backends.db import SessionStore
from django.test import RequestFactory
from django.utils.timezone import now

from dojo.authorization.roles_permissions import Roles
from dojo.location.models import Location
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
from dojo.url.models import URL
from dojo.url.ui.views import view_endpoint, view_endpoint_host
from unittests.dojo_test_case import DojoTestCase, skip_unless_v3

SHARED_HOST = "shared.epscope.example.com"


@skip_unless_v3
class EndpointViewFindingScopingTest(DojoTestCase):

    """Two products share one deduplicated Location, with one finding each."""

    @classmethod
    def setUpTestData(cls):
        prod_type = Product_Type.objects.create(name="epscope_pt")
        test_type, _ = Test_Type.objects.get_or_create(name="epscope_scan")

        def build(name, finding_title):
            product = Product.objects.create(name=name, description=name, prod_type=prod_type)
            engagement = Engagement.objects.create(
                product=product, name=f"{name}_eng",
                target_start=now().date(), target_end=now().date(),
            )
            test = Test.objects.create(
                engagement=engagement, test_type=test_type,
                target_start=now(), target_end=now(),
            )
            finding = Finding.objects.create(
                test=test, title=finding_title, severity="High",
                numerical_severity="S1", active=True, verified=True,
            )
            return product, finding

        cls.product_a, cls.finding_a = build("epscope_a", "Epscope Own Finding")
        cls.product_b, cls.finding_b = build("epscope_b", "Epscope Other Product Finding")

        # One deduplicated Location referenced by both products.
        url = URL.get_or_create_from_values(protocol="https", host=SHARED_HOST, path="login")
        cls.location = url.location
        for product, finding in ((cls.product_a, cls.finding_a), (cls.product_b, cls.finding_b)):
            cls.location.associate_with_finding(finding, audit_time=now())
            cls.location.associate_with_product(product)

        cls.user_a = Dojo_User.objects.create(username="epscope_user_a", is_active=True)
        Product_Member.objects.create(
            product=cls.product_a, user=cls.user_a, role=Role.objects.get(id=Roles.Reader),
        )
        cls.superuser = Dojo_User.objects.create(
            username="epscope_super", is_active=True, is_superuser=True,
        )

        # Titles are normalised on save, so compare against what was stored.
        cls.title_a = Finding.objects.get(pk=cls.finding_a.pk).title
        cls.title_b = Finding.objects.get(pk=cls.finding_b.pk).title

    def render_as(self, view, user):
        request = RequestFactory().get("/endpoint/", secure=True)
        request.user = user
        request.session = SessionStore()
        request._messages = FallbackStorage(request)
        with impersonate(user):
            response = view(request, self.location.id)
        self.assertEqual(response.status_code, 200)
        return response.content.decode("utf-8", "replace")

    def test_location_is_shared_by_both_products(self):
        """The premise: one Location row, referenced by both products."""
        self.assertEqual(Location.objects.filter(url__host=SHARED_HOST).count(), 1)
        self.assertEqual(
            sorted(reference.product_id for reference in self.location.products.all()),
            sorted([self.product_a.id, self.product_b.id]),
        )

    def test_views_exclude_other_products_findings(self):
        for view in (view_endpoint, view_endpoint_host):
            with self.subTest(view=view.__name__):
                body = self.render_as(view, self.user_a)
                self.assertIn(self.title_a, body)
                self.assertNotIn(self.title_b, body)

    def test_views_still_show_everything_to_a_superuser(self):
        for view in (view_endpoint, view_endpoint_host):
            with self.subTest(view=view.__name__):
                body = self.render_as(view, self.superuser)
                self.assertIn(self.title_a, body)
                self.assertIn(self.title_b, body)
