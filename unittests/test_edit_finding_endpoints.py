"""
Tests for endpoint add/remove behaviour on the Edit Finding view.

Covers two bugs introduced in the locations refactor (PR #14198):
1. Existing endpoints were not pre-selected in the edit form (Meta.exclude
   prevents Django from auto-populating the custom field from the instance).
2. Removing a selected endpoint had no effect because add_locations() always
   unioned the submitted selection with the pre-existing endpoints.
"""

import logging
from datetime import date
from types import SimpleNamespace

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.timezone import now

from dojo.finding.helper import add_locations
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

logger = logging.getLogger(__name__)


def _make_form(endpoints_qs, date_value=None):
    """Return a minimal form-like object accepted by add_locations()."""
    return SimpleNamespace(
        endpoints_to_add_list=[],
        cleaned_data={
            "endpoints": endpoints_qs,
            "date": date_value or date.today(),
        },
    )


@override_settings(V3_FEATURE_LOCATIONS=False)
class TestAddLocationsEndpoints(TestCase):

    """Unit tests for finding.helper.add_locations() in non-V3 (Endpoint) mode."""

    def setUp(self):
        product_type = Product_Type.objects.create(name="PT")
        self.product = Product.objects.create(name="P", prod_type=product_type)
        engagement = Engagement.objects.create(
            name="E", product=self.product, target_start=now(), target_end=now(),
        )
        test_type = Test_Type.objects.create(name="TT")
        self.test = Test.objects.create(
            engagement=engagement, test_type=test_type,
            target_start=now(), target_end=now(),
        )
        user = User.objects.create_user(username="u1", password="pass")  # noqa: S106
        self.finding = Finding.objects.create(
            title="F", severity="High", test=self.test, reporter=user,
        )
        self.ep1 = Endpoint.objects.create(host="host1.example.com", product=self.product)
        self.ep2 = Endpoint.objects.create(host="host2.example.com", product=self.product)

    def test_add_endpoint(self):
        """Submitting an endpoint that is not yet on the finding adds it."""
        form = _make_form(Endpoint.objects.filter(pk=self.ep1.pk))
        add_locations(self.finding, form)
        self.assertIn(self.ep1, self.finding.endpoints.all())

    def test_keep_existing_endpoint(self):
        """Re-submitting an already-associated endpoint keeps it."""
        self.finding.endpoints.add(self.ep1)

        form = _make_form(Endpoint.objects.filter(pk=self.ep1.pk))
        add_locations(self.finding, form)

        self.assertIn(self.ep1, self.finding.endpoints.all())

    def test_remove_endpoint(self):
        """Submitting an empty selection removes the previously-associated endpoint."""
        self.finding.endpoints.add(self.ep1)

        form = _make_form(Endpoint.objects.none())
        add_locations(self.finding, form, replace=True)

        self.assertNotIn(self.ep1, self.finding.endpoints.all())

    def test_switch_endpoint(self):
        """Deselecting one endpoint and selecting another replaces it."""
        self.finding.endpoints.add(self.ep1)

        form = _make_form(Endpoint.objects.filter(pk=self.ep2.pk))
        add_locations(self.finding, form, replace=True)

        self.assertNotIn(self.ep1, self.finding.endpoints.all())
        self.assertIn(self.ep2, self.finding.endpoints.all())

    def test_endpoint_status_created_on_add(self):
        """An Endpoint_Status record is created when an endpoint is added."""
        form = _make_form(Endpoint.objects.filter(pk=self.ep1.pk))
        add_locations(self.finding, form)

        self.assertTrue(
            Endpoint_Status.objects.filter(finding=self.finding, endpoint=self.ep1).exists(),
        )


@override_settings(V3_FEATURE_LOCATIONS=False)
class TestEditFindingEndpointView(TestCase):

    """View-level tests for EditFinding endpoint handling."""

    def _minimal_post_data(self, **overrides):
        data = {
            "title": self.finding.title,
            "date": "2024-01-01",
            "severity": "High",
            "description": "Test description",
            "active": "on",
            "verified": "",
            "false_p": "",
            "duplicate": "",
            "out_of_scope": "",
            "endpoints": [],
            "endpoints_to_add": "",
            "vulnerability_ids": "",
            "references": "",
            "mitigation": "",
            "impact": "",
            "steps_to_reproduce": "",
            "severity_justification": "",
        }
        data.update(overrides)
        return data

    def setUp(self):
        self.user = User.objects.create_user(
            username="tester", password="pass",  # noqa: S106
            is_staff=True, is_superuser=True,
        )
        self.client.force_login(self.user)
        product_type = Product_Type.objects.create(name="PT")
        self.product = Product.objects.create(name="P", prod_type=product_type)
        engagement = Engagement.objects.create(
            name="E", product=self.product, target_start=now(), target_end=now(),
        )
        test_type = Test_Type.objects.create(name="TT")
        self.test_obj = Test.objects.create(
            engagement=engagement, test_type=test_type,
            target_start=now(), target_end=now(),
        )
        self.finding = Finding.objects.create(
            title="Endpoint Test Finding",
            severity="High",
            test=self.test_obj,
            reporter=self.user,
        )
        self.endpoint = Endpoint.objects.create(
            host="vuln.example.com", product=self.product,
        )
        self.url = reverse("edit_finding", args=[self.finding.id])

    def test_get_preselects_existing_endpoints(self):
        """GET edit form has existing endpoints pre-selected as initial values."""
        self.finding.endpoints.add(self.endpoint)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        initial = list(response.context["form"].fields["endpoints"].initial)
        self.assertIn(self.endpoint, initial)

    def test_get_preselects_multiple_endpoints(self):
        """GET edit form pre-selects all associated endpoints, not just the first."""
        endpoint2 = Endpoint.objects.create(host="vuln2.example.com", product=self.product)
        self.finding.endpoints.add(self.endpoint)
        self.finding.endpoints.add(endpoint2)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        initial = list(response.context["form"].fields["endpoints"].initial)
        self.assertIn(self.endpoint, initial)
        self.assertIn(endpoint2, initial)

    def test_get_no_endpoints_when_none_associated(self):
        """GET edit form initial is empty when no endpoints are associated."""
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        initial = list(response.context["form"].fields["endpoints"].initial)
        self.assertEqual(initial, [])

    def test_post_removes_deselected_endpoint(self):
        """POST with empty endpoints list removes the previously-associated endpoint."""
        self.finding.endpoints.add(self.endpoint)

        response = self.client.post(self.url, self._minimal_post_data())

        self.assertIn(response.status_code, [200, 302])
        self.finding.refresh_from_db()
        self.assertNotIn(self.endpoint, self.finding.endpoints.all())

    def test_post_removes_endpoint_status_on_remove(self):
        """POST that removes an endpoint also cleans up its Endpoint_Status record."""
        self.finding.endpoints.add(self.endpoint)

        self.client.post(self.url, self._minimal_post_data())

        self.assertFalse(
            Endpoint_Status.objects.filter(finding=self.finding, endpoint=self.endpoint).exists(),
        )

    def test_post_keeps_selected_endpoint(self):
        """POST with an endpoint still selected keeps it on the finding."""
        self.finding.endpoints.add(self.endpoint)

        data = self._minimal_post_data(endpoints=[self.endpoint.pk])
        response = self.client.post(self.url, data)

        self.assertIn(response.status_code, [200, 302])
        self.finding.refresh_from_db()
        self.assertIn(self.endpoint, self.finding.endpoints.all())

    def test_post_keeps_all_selected_endpoints(self):
        """POST that keeps all endpoints selected preserves all of them."""
        endpoint2 = Endpoint.objects.create(host="vuln2.example.com", product=self.product)
        self.finding.endpoints.add(self.endpoint)
        self.finding.endpoints.add(endpoint2)

        data = self._minimal_post_data(endpoints=[self.endpoint.pk, endpoint2.pk])
        response = self.client.post(self.url, data)

        self.assertIn(response.status_code, [200, 302])
        self.finding.refresh_from_db()
        self.assertIn(self.endpoint, self.finding.endpoints.all())
        self.assertIn(endpoint2, self.finding.endpoints.all())
