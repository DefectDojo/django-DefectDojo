"""
The location read inside hash_code must honour a prefetched locations relation.

``Finding.get_locations()`` feeds the ``endpoints`` hash ingredient for the 13 scan types whose
``HASHCODE_FIELDS_PER_SCANNER`` includes it. Every caller of the hash paths prefetches that
relation -- the batch dedupe loader, ``build_candidate_scope_queryset`` and ``manage.py dedupe``
among them -- but the saved-locations read used ``finding.locations.filter(...)``, and
``.filter()`` on a related manager clones the queryset and drops ``_result_cache``. That bypassed
the prefetch entirely: every caller paid for a prefetch whose results were then discarded, then
took a query per location reference, plus a ``.count()`` that ran regardless of log level because
it sat inside string concatenation.

Query counts, not timings, so these cannot flake on machine speed.

The existing perf suites do not cover this. Their fixtures use scan types that do not hash
``endpoints``, so ``get_locations()`` is never reached there and their counts are unchanged by
this fix -- verified by running both before and after.
"""

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.utils import timezone

from dojo.importers.default_importer import DefaultImporter
from dojo.models import (
    Development_Environment,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
)
from dojo.tools.locations import LocationData

from .dojo_test_case import DojoTestCase

User = get_user_model()

# "Qualys Scan" hashes ["title", "severity", "endpoints"], so the reported locations really are
# part of hash_code for this scan type and get_locations() is reached.
SCAN_TYPE = "Qualys Scan"

URLS = [
    "https://zulu.example.com/three",
    "https://alpha.example.com/one",
    "https://mike.example.com/two",
]


@override_settings(V3_FEATURE_LOCATIONS=True)
class TestHashCodeLocationQueryCount(DojoTestCase):

    """Computing hash_code must not re-query locations the caller already prefetched."""

    def setUp(self):
        super().setUp()
        self.user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="hash code location queries")
        self.product, _ = Product.objects.get_or_create(
            name="hash code location queries product",
            description="test",
            prod_type=product_type,
        )
        self.engagement, _ = Engagement.objects.get_or_create(
            name="hash code location queries engagement",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.environment, _ = Development_Environment.objects.get_or_create(name="Development")
        test_type, _ = Test_Type.objects.get_or_create(name=SCAN_TYPE)
        self.test = Test.objects.create(
            engagement=self.engagement,
            test_type=test_type,
            scan_type=SCAN_TYPE,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    def _saved_finding_with_locations(self, urls):
        """Import one finding carrying ``urls`` as locations, the way a scan import does."""
        parsed = Finding(
            title="Insecure thing",
            severity="High",
            description="whatever",
            dynamic_finding=True,
            test=self.test,
        )
        parsed.unsaved_locations = [LocationData.url(url=url) for url in urls]

        importer = DefaultImporter(
            user=self.user,
            lead=self.user,
            scan_date=None,
            environment=self.environment,
            minimum_severity="Info",
            active=True,
            verified=True,
            sync=True,
            scan_type=SCAN_TYPE,
            engagement=self.engagement,
        )
        importer.create_test(SCAN_TYPE)
        imported = importer.process_findings([parsed])
        self.assertEqual(1, len(imported))
        return imported[0]

    def test_prefetched_locations_are_not_requeried(self):
        """
        The point of the fix. With the relation prefetched, the read comes from cache and costs
        nothing. Before, ``.filter()`` discarded the cache and this took a query for the filtered
        set, another for ``.count()``, and one per location reference.
        """
        finding = self._saved_finding_with_locations(URLS)

        prefetched = Finding.objects.filter(pk=finding.pk).prefetch_related("locations__location")[0]

        with self.assertNumQueries(0):
            prefetched.get_locations()

    def test_prefetching_only_the_references_still_queries_every_location(self):
        """
        Why callers have to prefetch two hops, not one.

        The read needs ``ref.location.location_value``, so prefetching just ``locations`` leaves a
        query per location reference. This is what makes ``locations__location`` (or a ``Prefetch``
        carrying ``select_related("location")``) the lookup callers actually want -- and what an
        unprefetched read costs, one per location.
        """
        finding = self._saved_finding_with_locations(URLS)

        shallow = Finding.objects.filter(pk=finding.pk).prefetch_related("locations")[0]

        # One query per location, because only the reference level was prefetched.
        with self.assertNumQueries(len(URLS)):
            shallow.get_locations()

    def test_the_hash_ingredient_is_unchanged_by_narrowing_in_python(self):
        """
        Narrowing the relation in Python instead of SQL must produce the same string: URL
        locations only, deduplicated and sorted. Prefetched and unprefetched must agree too.
        """
        finding = self._saved_finding_with_locations(URLS)

        unprefetched = Finding.objects.get(pk=finding.pk)
        prefetched = Finding.objects.filter(pk=finding.pk).prefetch_related("locations__location")[0]

        self.assertEqual(prefetched.get_locations(), unprefetched.get_locations())
        self.assertEqual(
            unprefetched.get_locations(),
            "".join(sorted(URLS)),
            msg="the ingredient must stay the sorted, deduplicated canonical location values",
        )

    def test_the_hash_code_is_unchanged_by_narrowing_in_python(self):
        """End to end: the stored hash still matches a recomputation from the saved finding."""
        finding = self._saved_finding_with_locations(URLS)
        finding.refresh_from_db()

        self.assertEqual(finding.hash_code, finding.compute_hash_code())
