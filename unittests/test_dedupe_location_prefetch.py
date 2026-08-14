"""
The location prefetch the dedupe and rehash querysets need, in one place.

Which location relation to prefetch is a property of what ``Finding.get_locations()`` reads, not
of any individual caller, but it was spelled out separately at every call site. That drifts: the
hash-recompute paths disagreed about it for months, and the batch dedupe loader prefetched the
deprecated ``endpoints`` relation, which raises under ``V3_FEATURE_LOCATIONS`` once an instance has
migrated from endpoints (see #15508).

``location_prefetch_lookups()`` is that decision, once. These assertions are about queryset
shape, so they need no fixtures and cannot flake on machine speed.
"""
import logging

from django.db.models import Prefetch
from django.test import override_settings
from django.utils import timezone

from dojo.finding.deduplication import build_candidate_scope_queryset
from dojo.location.queries import location_prefetch_lookups
from dojo.models import Engagement, Product, Product_Type, Test, Test_Type

from .dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)


class TestLocationPrefetchLookups(DojoTestCase):

    """The lookup has to follow the location model in use -- no database needed."""

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_v3_prefetches_url_locations_and_not_endpoints(self):
        lookups = location_prefetch_lookups()
        self.assertEqual(lookups, ["locations__location__url"])
        self.assertNotIn("endpoints", lookups)

    @override_settings(V3_FEATURE_LOCATIONS=False)
    def test_pre_v3_prefetches_endpoints(self):
        # TODO: Delete this after the move to Locations
        self.assertEqual(location_prefetch_lookups(), ["endpoints"])

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_it_reaches_the_url_the_hash_actually_reads(self):
        """
        ``get_locations()`` reads ``location_ref.location.url``, so stopping the prefetch at
        ``locations`` leaves a query per reference. The lookup has to traverse the whole path.
        """
        self.assertEqual(location_prefetch_lookups(), ["locations__location__url"])

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_prefix_reaches_the_finding_through_a_relation(self):
        """For callers that page a model reaching the finding through a relation."""
        self.assertEqual(
            location_prefetch_lookups("finding__"),
            ["finding__locations__location__url"],
        )


def _lookup_strings(queryset):
    """The lookup path of every prefetch on a queryset, Prefetch objects included."""
    return [
        lookup.prefetch_through if isinstance(lookup, Prefetch) else str(lookup)
        for lookup in queryset._prefetch_related_lookups
    ]


class TestDedupeQuerysetsUseTheHelper(DojoTestCase):

    """Every dedupe/rehash queryset picks its location lookup the same way."""

    def setUp(self):
        super().setUp()
        product_type = Product_Type.objects.create(name="Org for prefetch shape")
        product = Product.objects.create(
            name="Product for prefetch shape",
            description="shape fixture",
            prod_type=product_type,
        )
        engagement = Engagement.objects.create(
            name="Engagement",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.test = Test.objects.create(
            engagement=engagement,
            test_type=Test_Type.objects.get_or_create(name="Manual Test")[0],
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    @override_settings(V3_FEATURE_LOCATIONS=True)
    def test_candidate_scope_queryset_under_v3(self):
        for mode in ("deduplication", "reimport"):
            with self.subTest(mode=mode):
                lookups = _lookup_strings(build_candidate_scope_queryset(self.test, mode=mode))
                self.assertIn("locations__location__url", lookups)
                self.assertNotIn("endpoints", lookups)

    @override_settings(V3_FEATURE_LOCATIONS=False)
    def test_candidate_scope_queryset_pre_v3(self):
        # TODO: Delete this after the move to Locations
        for mode in ("deduplication", "reimport"):
            with self.subTest(mode=mode):
                lookups = _lookup_strings(build_candidate_scope_queryset(self.test, mode=mode))
                self.assertIn("endpoints", lookups)
                self.assertNotIn("locations__location__url", lookups)
