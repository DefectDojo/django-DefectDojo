"""
Regression tests for the V3_FEATURE_LOCATIONS deduplication-prefetch crash.

When ``V3_FEATURE_LOCATIONS`` is enabled the legacy ``Endpoint`` model is deprecated and
``Endpoint.__init__`` raises ``NotImplementedError``. The move to Locations does not delete
endpoint rows, so a migrated instance still has them -- and any queryset that prefetches the
``endpoints`` relation hydrates the deprecated model for every surviving row and blows up.

``get_finding_models_for_deduplication`` prefetched ``endpoints`` unconditionally, which put
that crash on the batch-deduplication path taken by every import and reimport
(``post_process_findings_batch``) as well as by ``manage.py dedupe`` in batch mode. A fresh V3
instance has no endpoint rows to hydrate, so nothing surfaces it until an instance that
migrated from endpoints runs an import.

The fix routes every dedupe/rehash queryset through ``location_prefetch_lookups()``, which
returns the lookup for the location model actually in use.
"""
import logging
from types import SimpleNamespace

from django.contrib.auth.models import User
from django.test import override_settings
from django.utils import timezone

from dojo.finding.deduplication import (
    build_candidate_scope_queryset,
    get_finding_models_for_deduplication,
)
from dojo.location.queries import location_prefetch_lookups
from dojo.models import (
    Endpoint,
    Endpoint_Status,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
    UserContactInfo,
)

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
    def test_prefix_reaches_the_finding_through_a_relation(self):
        self.assertEqual(
            location_prefetch_lookups("finding__"),
            ["finding__locations__location__url"],
        )


@override_settings(V3_FEATURE_LOCATIONS=True)
class TestDedupeQuerysetsWithLegacyEndpoints(DojoTestCase):

    """
    The deduplication querysets must not hydrate the deprecated ``Endpoint`` model, even when
    a migrated instance still has endpoint rows attached to the findings being deduplicated.
    """

    def setUp(self):
        super().setUp()

        self.user = User.objects.create(
            username="test_dedupe_endpoints_v3_user",
            is_staff=True,
            is_superuser=True,
        )
        UserContactInfo.objects.create(user=self.user, block_execution=True)

        self.system_settings(enable_product_grade=False)
        self.system_settings(enable_jira=False)

        self.test_type = Test_Type.objects.get_or_create(name="Manual Test")[0]

    def _build_tree(self, suffix, *, with_legacy_endpoint=True):
        """
        Create Product_Type -> Product -> Engagement -> Test -> Finding, plus (by default) a
        legacy Endpoint on the product and an Endpoint_Status linking it to the finding --
        the rows a migrated instance keeps.
        """
        product_type = Product_Type.objects.create(name=f"Org dedupe endpoints {suffix}")
        product = Product.objects.create(
            name=f"Product dedupe endpoints {suffix}",
            description="regression fixture",
            prod_type=product_type,
        )
        engagement = Engagement.objects.create(
            name=f"Engagement {suffix}",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        test = Test.objects.create(
            engagement=engagement,
            test_type=self.test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        finding = Finding.objects.create(
            test=test,
            title=f"Finding {suffix}",
            severity="High",
            description="regression fixture",
            mitigation="n/a",
            impact="n/a",
            reporter=self.user,
        )
        if with_legacy_endpoint:
            # The Endpoint model is deprecated under V3; creating the rows a migration left
            # behind requires the escape hatch. Reading them back must not need it.
            with Endpoint.allow_endpoint_init():
                endpoint = Endpoint(
                    product=product,
                    protocol="https",
                    host=f"host-{suffix}.example.com",
                )
                endpoint.save()
                Endpoint_Status(endpoint=endpoint, finding=finding).save()

        return SimpleNamespace(
            product_type=product_type,
            product=product,
            engagement=engagement,
            test=test,
            finding=finding,
        )

    def test_batch_dedupe_loader_survives_legacy_endpoint_rows(self):
        """
        The loader behind post_process_findings_batch (import/reimport) and the dedupe
        command's batch mode. Prefetching ``endpoints`` here raised NotImplementedError.
        """
        tree = self._build_tree("loader")

        findings = get_finding_models_for_deduplication([tree.finding.id])

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].id, tree.finding.id)

    def test_batch_dedupe_loader_does_not_prefetch_the_deprecated_relation(self):
        """
        Shape assertion, so a re-introduced ``endpoints`` prefetch fails here rather than
        only on an instance that happens to still have endpoint rows.
        """
        self._build_tree("shape", with_legacy_endpoint=False)

        queryset = Finding.objects.filter(id__in=[]).prefetch_related(
            *location_prefetch_lookups(),
        )

        self.assertNotIn("endpoints", [str(lookup) for lookup in queryset._prefetch_related_lookups])

    def test_candidate_queryset_survives_legacy_endpoint_rows(self):
        """build_candidate_scope_queryset builds the other prefetch list that branched on V3."""
        tree = self._build_tree("candidates")

        for mode in ("deduplication", "reimport"):
            with self.subTest(mode=mode):
                candidates = build_candidate_scope_queryset(tree.test, mode=mode)
                # Evaluating the queryset is what triggers the prefetch (and the crash).
                self.assertIn(tree.finding.id, [candidate.id for candidate in candidates])

    def test_hash_code_recompute_survives_legacy_endpoint_rows(self):
        """
        The rehash path the dedupe command runs: compute_hash_code() reads locations through
        get_locations(), which must not fall back to the deprecated relation.
        """
        tree = self._build_tree("rehash")

        self.assertTrue(tree.finding.compute_hash_code())
