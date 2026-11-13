"""
Regression tests for host grouping on the V3 hosts views.

With ``V3_FEATURE_LOCATIONS`` enabled, the hosts views group URL locations
by host with ``.distinct("url__host")`` before handing the queryset to
``URLFilter``. ``URLFilter.qs`` runs the location authorization filter a
second time, and for non-superusers that filter used to append a plain
``.distinct()`` which replaced the ``DISTINCT ON`` fields set by the view.
The result was one row per location instead of one row per host (issue
#16739).

These tests pin the contract for both kinds of user: the hosts views and
their counts show one row per host.
"""
from django.test import override_settings
from django.urls import reverse

from dojo.models import Dojo_User, Product, Product_Type
from dojo.url.models import URL
from unittests.dojo_test_case import DojoTestCase, skip_unless_v3


@override_settings(V3_FEATURE_LOCATIONS=True, SECURE_SSL_REDIRECT=False)
@skip_unless_v3
class HostsViewGroupingTests(DojoTestCase):

    """One product, one host with three URL locations, one reader."""

    @classmethod
    def setUpTestData(cls):
        cls.prod_type = Product_Type.objects.create(name="v3_hosts_grouping_pt")
        cls.product = Product.objects.create(
            name="v3_hosts_grouping_product",
            description="a",
            prod_type=cls.prod_type,
        )
        cls.reader = Dojo_User.objects.create(username="v3_hosts_grouping_reader", is_active=True)
        cls.product.authorized_users.add(cls.reader)

        cls.host = "v3-hosts.example.test"
        for value in (
            f"https://{cls.host}:443/a",
            f"http://{cls.host}:8080/b",
            f"https://{cls.host}:8443/c",
        ):
            url = URL.get_or_create_from_object(URL.from_value(value))
            url.location.associate_with_product(cls.product)

    def _hosts_page(self):
        response = self.client.get(reverse("endpoint_host"))
        self.assertEqual(response.status_code, 200)
        return response

    def test_hosts_view_one_row_per_host_for_reader(self):
        self.client.force_login(self.reader)
        response = self._hosts_page()
        self.assertEqual(len(response.context["locations"]), 1)
        self.assertEqual(response.context["location_count"], 1)

    def test_hosts_view_one_row_per_host_for_superuser(self):
        superuser = Dojo_User.objects.create(
            username="v3_hosts_grouping_super",
            is_active=True,
            is_superuser=True,
        )
        self.client.force_login(superuser)
        response = self._hosts_page()
        self.assertEqual(len(response.context["locations"]), 1)
        self.assertEqual(response.context["location_count"], 1)
