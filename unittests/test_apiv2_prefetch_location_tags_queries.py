"""
``?prefetch=location`` on the location reference endpoints reads each location's tags once per page.

``LocationSerializer`` returns ``tags`` and ``inherited_tags`` through ``Location.readable_tags``,
which checks whether the caller may read the row's shared tag set and then reads both tag
relations. The prefetcher serialized every prefetched location without loading either, so a page
of N references to N distinct locations cost a readability check plus two tag reads per location.

These tests pin a page's query count as flat in the number of prefetched locations, and check
that the prefetched payload still carries each location's own tags.
"""

from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.utils.timezone import now

from dojo.location.models import Location, LocationFindingReference
from dojo.location.status import FindingLocationStatus
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
)
from unittests.dojo_test_case import DojoAPITestCase


@override_settings(V3_FEATURE_LOCATIONS=True, SECURE_SSL_REDIRECT=False)
class PrefetchLocationTagsQueryCountTest(DojoAPITestCase):

    @classmethod
    def setUpTestData(cls):
        prod_type, _ = Product_Type.objects.get_or_create(name="PrefetchLocationTags PT")
        test_type, _ = Test_Type.objects.get_or_create(name="PrefetchLocationTags Scan")
        cls.admin = Dojo_User.objects.create_superuser(
            username="admin",
            email="admin@prefetch-location-tags.example",
            password="prefetch-location-tags-not-a-real-password",  # noqa: S106 -- test-only account
        )
        product = Product.objects.create(name="PrefetchLocationTags Product", description="n/a", prod_type=prod_type)
        engagement = Engagement.objects.create(
            name="PrefetchLocationTags Engagement", product=product, target_start=now(), target_end=now(),
        )
        cls.test = Test.objects.create(
            engagement=engagement, test_type=test_type, target_start=now(), target_end=now(), lead=cls.admin,
        )

    def setUp(self):
        self.login_as_admin()

    def _finding_with_locations(self, label, count):
        finding = Finding.objects.create(
            title=f"PrefetchLocationTags {label}",
            test=self.test,
            reporter=self.admin,
            severity="Info",
            numerical_severity="S4",
        )
        for index in range(count):
            location = Location.objects.create(
                location_type="URL",
                location_value=f"https://{label}-{index}.prefetch-location-tags.example.com/",
            )
            location.tags.add(f"{label}-tag-{index}")
            LocationFindingReference.objects.create(
                location=location, finding=finding, status=FindingLocationStatus.Active,
            )
        return finding

    def _get(self, finding):
        return self.client.get(
            "/api/v2/location_findings/",
            {"prefetch": "location", "finding_includes": str(finding.pk), "limit": 250},
            format="json",
        )

    def _query_count(self, finding):
        # Warm per-process caches (system settings, feature flags) so they don't skew the first count
        self._get(finding)
        with CaptureQueriesContext(connection) as queries:
            response = self._get(finding)
        self.assertEqual(200, response.status_code, response.content[:500])
        return len(queries)

    def test_query_count_does_not_grow_with_prefetched_locations(self):
        few = self._finding_with_locations("few", 2)
        many = self._finding_with_locations("many", 8)
        self.assertEqual(self._query_count(few), self._query_count(many))

    def test_prefetched_locations_carry_their_own_tags(self):
        finding = self._finding_with_locations("tags", 3)
        response = self._get(finding)
        self.assertEqual(200, response.status_code, response.content[:500])
        prefetched = response.json()["prefetch"]["location"]
        self.assertEqual(3, len(prefetched))
        for data in prefetched.values():
            index = data["location_value"].split("-")[1].split(".")[0]
            self.assertEqual([f"tags-tag-{index}"], data["tags"])
