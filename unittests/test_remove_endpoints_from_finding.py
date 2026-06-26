"""
Tests for the "Remove from Finding" bulk action on the View Finding page.

Covers both the non-V3 (Endpoint/Endpoint_Status) and V3 (Location/
LocationFindingReference) paths via the respective bulk-update views.

The two test classes are gated by skipUnless so that each class only runs
against the URL configuration that is active for its code path:
- TestRemoveEndpointsFromFindingView  — skipped when V3_FEATURE_LOCATIONS=True
- TestRemoveLocationsFromFindingView  — skipped when V3_FEATURE_LOCATIONS=False
"""

import logging
from unittest import skipUnless

from django.conf import settings
from django.test import TestCase
from django.urls import reverse
from django.utils.timezone import now

from dojo.location.models import LocationFindingReference
from dojo.models import (
    Endpoint,
    Endpoint_Status,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
    User,
)
from dojo.url.models import URL

logger = logging.getLogger(__name__)


def _make_superuser(username):
    return User.objects.create_user(
        username=username,
        password="pass",  # noqa: S106
        is_staff=True,
        is_superuser=True,
    )


def _make_finding(test, reporter):
    return Finding.objects.create(
        title="Bulk Remove Test Finding",
        severity="High",
        test=test,
        reporter=reporter,
    )


def _make_product_tree(product_name="P"):
    pt = Product_Type.objects.create(name="PT")
    product = Product.objects.create(name=product_name, prod_type=pt, description="Test product")
    engagement = Engagement.objects.create(
        name="E", product=product, target_start=now(), target_end=now(),
    )
    test_type = Test_Type.objects.create(name="TT")
    test = Test.objects.create(
        engagement=engagement, test_type=test_type,
        target_start=now(), target_end=now(),
    )
    return product, test


@skipUnless(not settings.V3_FEATURE_LOCATIONS, "Non-V3 endpoint path only")
class TestRemoveEndpointsFromFindingView(TestCase):

    """Tests for endpoint_status_bulk_update (non-V3 path)."""

    def setUp(self):
        self.user = _make_superuser("tester")
        self.client.force_login(self.user)
        self.product, self.test_obj = _make_product_tree()
        self.finding = _make_finding(self.test_obj, self.user)
        self.ep1 = Endpoint.objects.create(host="ep1.example.com", product=self.product)
        self.ep2 = Endpoint.objects.create(host="ep2.example.com", product=self.product)
        self.url = reverse("endpoints_status_bulk", args=[self.finding.id])

    def _post(self, endpoint_ids, *, remove=False):
        data = {
            "return_url": reverse("view_finding", args=[self.finding.id]),
            "endpoints_to_update": endpoint_ids,
        }
        if remove:
            data["remove_from_finding"] = "1"
        return self.client.post(self.url, data)

    def test_remove_single_endpoint(self):
        """POST with remove_from_finding removes the selected endpoint from the finding."""
        self.finding.endpoints.add(self.ep1)

        response = self._post([self.ep1.pk], remove=True)

        self.assertIn(response.status_code, [200, 302])
        self.assertNotIn(self.ep1, self.finding.endpoints.all())

    def test_remove_cleans_up_endpoint_status(self):
        """Removing an endpoint also deletes its Endpoint_Status record."""
        self.finding.endpoints.add(self.ep1)
        self.assertTrue(
            Endpoint_Status.objects.filter(finding=self.finding, endpoint=self.ep1).exists(),
        )

        self._post([self.ep1.pk], remove=True)

        self.assertFalse(
            Endpoint_Status.objects.filter(finding=self.finding, endpoint=self.ep1).exists(),
        )

    def test_remove_only_selected_endpoint(self):
        """Only the selected endpoint is removed; others remain."""
        self.finding.endpoints.add(self.ep1)
        self.finding.endpoints.add(self.ep2)

        self._post([self.ep1.pk], remove=True)

        self.assertNotIn(self.ep1, self.finding.endpoints.all())
        self.assertIn(self.ep2, self.finding.endpoints.all())

    def test_remove_multiple_endpoints(self):
        """Multiple endpoints can be removed in a single request."""
        self.finding.endpoints.add(self.ep1)
        self.finding.endpoints.add(self.ep2)

        self._post([self.ep1.pk, self.ep2.pk], remove=True)

        self.assertNotIn(self.ep1, self.finding.endpoints.all())
        self.assertNotIn(self.ep2, self.finding.endpoints.all())

    def test_remove_without_flag_does_not_remove(self):
        """Submitting endpoint IDs without remove_from_finding does not remove them."""
        self.finding.endpoints.add(self.ep1)

        # Post without remove flag and without any status checkboxes — triggers
        # the "nothing selected" error branch, but must NOT remove the endpoint.
        self._post([self.ep1.pk], remove=False)

        self.assertIn(self.ep1, self.finding.endpoints.all())

    def test_remove_redirects(self):
        """The view redirects after a successful remove."""
        self.finding.endpoints.add(self.ep1)
        return_url = reverse("view_finding", args=[self.finding.id])

        response = self._post([self.ep1.pk], remove=True)

        self.assertRedirects(response, return_url, fetch_redirect_response=False)


@skipUnless(settings.V3_FEATURE_LOCATIONS, "V3 locations path only")
class TestRemoveLocationsFromFindingView(TestCase):

    """Tests for finding_location_bulk_update (V3/Locations path)."""

    def setUp(self):
        self.user = _make_superuser("tester")
        self.client.force_login(self.user)
        self.product, self.test_obj = _make_product_tree()
        self.finding = _make_finding(self.test_obj, self.user)

        self.url1 = URL.get_or_create_from_values(host="loc1.example.com")
        self.url2 = URL.get_or_create_from_values(host="loc2.example.com")
        self.loc1 = self.url1.location
        self.loc2 = self.url2.location

        self.url = reverse("endpoints_status_bulk", args=[self.finding.id])

    def _associate(self, location):
        ref, _ = LocationFindingReference.objects.get_or_create(
            location=location, finding=self.finding,
        )
        return ref

    def _post(self, location_ids, *, remove=False):
        data = {
            "return_url": reverse("view_finding", args=[self.finding.id]),
            "endpoints_to_update": location_ids,
        }
        if remove:
            data["remove_from_finding"] = "1"
        return self.client.post(self.url, data)

    def test_remove_single_location(self):
        """POST with remove_from_finding removes the selected location from the finding."""
        self._associate(self.loc1)

        response = self._post([self.loc1.pk], remove=True)

        self.assertIn(response.status_code, [200, 302])
        self.assertFalse(
            LocationFindingReference.objects.filter(
                finding=self.finding, location=self.loc1,
            ).exists(),
        )

    def test_remove_only_selected_location(self):
        """Only the selected location is removed; others remain."""
        self._associate(self.loc1)
        self._associate(self.loc2)

        self._post([self.loc1.pk], remove=True)

        self.assertFalse(
            LocationFindingReference.objects.filter(
                finding=self.finding, location=self.loc1,
            ).exists(),
        )
        self.assertTrue(
            LocationFindingReference.objects.filter(
                finding=self.finding, location=self.loc2,
            ).exists(),
        )

    def test_remove_multiple_locations(self):
        """Multiple locations can be removed in a single request."""
        self._associate(self.loc1)
        self._associate(self.loc2)

        self._post([self.loc1.pk, self.loc2.pk], remove=True)

        self.assertFalse(
            LocationFindingReference.objects.filter(
                finding=self.finding, location__in=[self.loc1, self.loc2],
            ).exists(),
        )

    def test_remove_without_flag_does_not_remove(self):
        """Submitting location IDs without remove_from_finding does not remove them."""
        self._associate(self.loc1)

        self._post([self.loc1.pk], remove=False)

        self.assertTrue(
            LocationFindingReference.objects.filter(
                finding=self.finding, location=self.loc1,
            ).exists(),
        )

    def test_remove_redirects(self):
        """The view redirects after a successful remove."""
        self._associate(self.loc1)
        return_url = reverse("view_finding", args=[self.finding.id])

        response = self._post([self.loc1.pk], remove=True)

        self.assertRedirects(response, return_url, fetch_redirect_response=False)
