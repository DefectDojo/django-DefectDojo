"""
Regression: merging findings copies endpoints onto the destination finding but drops locations.

Reported as issue #15377. ``merge_finding_product`` (``dojo/finding/ui/views.py``) only copied the
legacy ``Endpoint`` m2m when "Add Endpoints" was checked, so under ``V3_FEATURE_LOCATIONS`` the
destination finding came out of the merge with none of the source findings' locations.
"""

import logging

from django.contrib.auth.models import User
from django.test import Client, override_settings
from django.urls import reverse
from django.utils import timezone
from parameterized import parameterized

from dojo.location.models import LocationFindingReference
from dojo.location.status import FindingLocationStatus
from dojo.models import (
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
    UserContactInfo,
)
from dojo.url.models import URL

from .dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)


@override_settings(V3_FEATURE_LOCATIONS=True, SECURE_SSL_REDIRECT=False)
class TestMergeFindingsLocations(DojoTestCase):

    """Locations of the merged findings must land on the destination finding."""

    def setUp(self):
        super().setUp()

        self.admin = User.objects.create(
            username="test_merge_locations_admin",
            is_staff=True,
            is_superuser=True,
        )
        UserContactInfo.objects.create(user=self.admin, block_execution=True)

        self.ui_client = Client()
        self.ui_client.force_login(self.admin)

        self.system_settings(enable_jira=False)
        self.system_settings(enable_github=False)

        now = timezone.now()
        test_type = Test_Type.objects.get_or_create(name="Manual Test")[0]
        product_type = Product_Type.objects.create(name="Org for merge locations")
        self.product = Product.objects.create(
            name="Product for merge locations",
            description="regression fixture",
            prod_type=product_type,
        )
        engagement = Engagement.objects.create(
            name="Engagement for merge locations",
            product=self.product,
            target_start=now,
            target_end=now,
        )
        self.test = Test.objects.create(
            engagement=engagement,
            test_type=test_type,
            target_start=now,
            target_end=now,
        )

    def _make_finding(self, title):
        return Finding.objects.create(
            test=self.test,
            title=title,
            severity="High",
            description="regression fixture",
            mitigation="n/a",
            impact="n/a",
            reporter=self.admin,
        )

    def _add_location(self, finding, host, *, status=FindingLocationStatus.Active):
        url = URL(protocol="https", host=host)
        url.clean()
        url = URL.get_or_create_from_object(url)
        LocationFindingReference.objects.create(
            location=url.location,
            finding=finding,
            status=status,
        )
        return url.location

    def _merge(self, destination, sources, *, add_endpoints):
        finding_ids = [destination.id, *[f.id for f in sources]]
        query = "&".join(f"finding_to_update={fid}" for fid in finding_ids)
        payload = {
            "finding_to_merge_into": destination.id,
            "findings_to_merge": [f.id for f in sources],
            "append_description": "on",
            "finding_action": "inactive",
        }
        if add_endpoints:
            payload["add_endpoints"] = "on"
        return self.ui_client.post(
            f"{reverse('merge_finding_product', kwargs={'pid': self.product.id})}?{query}",
            payload,
        )

    @parameterized.expand([(True,), (False,)])
    def test_merge_copies_locations_when_requested(self, add_endpoints):
        """Locations follow the "Add Endpoints" choice: copied when checked, left alone when not."""
        destination = self._make_finding("Merge locations destination")
        source = self._make_finding("Merge locations source")
        source_location = self._add_location(source, "merge-source.example.com")

        response = self._merge(destination, [source], add_endpoints=add_endpoints)
        self.assertEqual(response.status_code, 302)

        persisted = list(
            LocationFindingReference.objects.filter(finding=destination).values_list(
                "location__location_value", flat=True,
            ),
        )
        expected = ["https://merge-source.example.com"] if add_endpoints else []
        self.assertEqual(
            sorted(persisted), expected,
            msg=f"add_endpoints={add_endpoints}: expected {expected}, destination has {persisted}",
        )
        # The source finding keeps its own location reference; locations are copied, not moved.
        self.assertTrue(
            LocationFindingReference.objects.filter(finding=source, location=source_location).exists(),
            msg="the source finding lost its location reference during the merge",
        )

    def test_merge_keeps_destination_reference_for_shared_location(self):
        """A location on both findings must not raise on the unique (location, finding) constraint."""
        destination = self._make_finding("Merge shared location destination")
        source = self._make_finding("Merge shared location source")
        shared = self._add_location(destination, "merge-shared.example.com")
        self._add_location(source, "merge-shared.example.com", status=FindingLocationStatus.Mitigated)

        response = self._merge(destination, [source], add_endpoints=True)
        self.assertEqual(response.status_code, 302)

        references = LocationFindingReference.objects.filter(finding=destination, location=shared)
        self.assertEqual(
            references.count(), 1,
            msg=f"expected a single reference to the shared location, found {references.count()}",
        )
        self.assertEqual(
            references.first().status, FindingLocationStatus.Active,
            msg="the destination finding's own status must win over the merged finding's status",
        )

    def test_merge_copies_locations_from_every_source_finding(self):
        destination = self._make_finding("Merge multi destination")
        source_a = self._make_finding("Merge multi source A")
        source_b = self._make_finding("Merge multi source B")
        self._add_location(source_a, "merge-multi-a.example.com")
        self._add_location(source_b, "merge-multi-b.example.com")

        response = self._merge(destination, [source_a, source_b], add_endpoints=True)
        self.assertEqual(response.status_code, 302)

        persisted = sorted(
            LocationFindingReference.objects.filter(finding=destination).values_list(
                "location__location_value", flat=True,
            ),
        )
        expected = ["https://merge-multi-a.example.com", "https://merge-multi-b.example.com"]
        self.assertEqual(persisted, expected, msg=f"expected {expected}, destination has {persisted}")
