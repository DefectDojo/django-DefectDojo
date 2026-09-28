"""A shared Location's action history must not hand one product another product's audit context."""
from django.contrib.contenttypes.models import ContentType
from django.test import override_settings
from django.urls import reverse

from dojo.location.models import Location
from dojo.models import Dojo_User, Product, Product_Type

from .dojo_test_case import DojoTestCase, skip_unless_v3

A_ADDR = "192.0.2.10"
B_ADDR = "192.0.2.20"


# The Location views and URL names only exist when V3_FEATURE_LOCATIONS is on at startup,
# so overriding the setting per test is not enough.
@skip_unless_v3
@override_settings(V3_FEATURE_LOCATIONS=True, ENABLE_AUDITLOG=True)
class LocationHistoryScopeTest(DojoTestCase):

    def _member(self, username, product=None):
        user = Dojo_User.objects.create(username=username, is_staff=False, is_superuser=False)
        user.set_password("pw")
        user.save()
        if product is not None:
            product.authorized_users.add(user)
        return user

    def setUp(self):
        prod_type = Product_Type.objects.create(name="loc-history-pt")
        self.product_a = Product.objects.create(name="loc-history-a", prod_type=prod_type, description="a")
        self.product_b = Product.objects.create(name="loc-history-b", prod_type=prod_type, description="b")
        self.user_a = self._member("loc_history_a", self.product_a)
        self.user_b = self._member("loc_history_b", self.product_b)
        self.outsider = self._member("loc_history_out")

    def _add_url(self, user, product, host, addr):
        self.client.force_login(user)
        response = self.client.post(
            reverse("add_endpoint_to_product", args=(product.id,)),
            {"protocol": "https", "host": host, "path": "context", "tags": ""},
            REMOTE_ADDR=addr,
        )
        self.client.logout()
        return response

    def _history(self, user, location):
        content_type_id = ContentType.objects.get_for_model(Location).id
        self.client.force_login(user)
        response = self.client.get(f"/history/{content_type_id}/{location.id}", REMOTE_ADDR=A_ADDR)
        self.client.logout()
        return response

    def test_shared_location_history_is_denied_to_a_partial_viewer(self):
        host = "shared.history.test"
        self.assertEqual(self._add_url(self.user_b, self.product_b, host, B_ADDR).status_code, 302)
        location = Location.objects.get(url__host=host)
        self.assertEqual(self._add_url(self.user_a, self.product_a, host, A_ADDR).status_code, 302)
        self.assertEqual(location.products.count(), 2)

        # The OS 403 handler renders with status 400.
        self.assertIn(self._history(self.user_a, location).status_code, (400, 403))

    def test_unshared_location_history_stays_readable(self):
        host = "own.history.test"
        self.assertEqual(self._add_url(self.user_b, self.product_b, host, B_ADDR).status_code, 302)
        location = Location.objects.get(url__host=host)

        response = self._history(self.user_b, location)
        self.assertEqual(response.status_code, 200)
        self.assertIn(B_ADDR, response.content.decode())

    def test_non_member_is_denied(self):
        host = "outsider.history.test"
        self.assertEqual(self._add_url(self.user_b, self.product_b, host, B_ADDR).status_code, 302)
        location = Location.objects.get(url__host=host)

        self.assertIn(self._history(self.outsider, location).status_code, (400, 403))
