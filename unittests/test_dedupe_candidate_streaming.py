"""
Regression: loading uid/hash dedupe candidates held the whole candidate result set in memory.

``find_candidates_for_deduplication_uid_or_hash`` evaluated its candidate queryset in one go:
the complete result set was fetched into the database client's buffer, cached on the queryset
and prefetched for every candidate id at once. On a product where many existing findings share
the batch's hash codes or unique ids, that pushed a single post-processing task past the worker's
memory limit during a large reimport.

The candidates are now streamed in chunks, and candidates from the same test share one Test /
Engagement / Test_Type instance instead of each carrying its own ``select_related`` copy. These
tests pin that the maps it returns are exactly the ones the unchunked evaluation produced,
whatever the chunk size, that the candidate queryset is walked with ``iterator(chunk_size=...)``
instead of being materialised whole, and that the shared relations carry the same values.
"""

import logging
from unittest import mock

from django.db import connection
from django.db.models import Q, QuerySet
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from dojo.finding import deduplication
from dojo.finding.deduplication import (
    build_candidate_scope_queryset,
    find_candidates_for_deduplication_uid_or_hash,
)
from dojo.models import (
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
    User,
    UserContactInfo,
)

from .dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_UNRELATED = "c" * 64


def _ids(bucketed):
    return {key: [finding.id for finding in findings] for key, findings in bucketed.items()}


def _unchunked_reference(test, findings, mode):
    """The candidate maps as the previous, fully materialised evaluation built them."""
    base_queryset = build_candidate_scope_queryset(test, mode=mode)
    hash_codes = {f.hash_code for f in findings if f.hash_code is not None}
    unique_ids = {f.unique_id_from_tool for f in findings if f.unique_id_from_tool is not None}
    cond = Q(hash_code__isnull=False, hash_code__in=hash_codes) | (
        Q(unique_id_from_tool__isnull=False, unique_id_from_tool__in=unique_ids) & Q(test__test_type=test.test_type)
    )
    existing_qs = base_queryset.filter(cond)
    if mode == "deduplication":
        existing_qs = existing_qs.exclude(duplicate=True)
    by_hash, by_uid = {}, {}
    for ef in list(existing_qs.order_by("id")):
        if ef.hash_code is not None:
            by_hash.setdefault(ef.hash_code, []).append(ef)
        if ef.unique_id_from_tool is not None:
            by_uid.setdefault(ef.unique_id_from_tool, []).append(ef)
    return by_uid, by_hash


class TestUidOrHashCandidatesAreStreamed(DojoTestCase):

    def setUp(self):
        super().setUp()
        self.user = User.objects.create(username="dedupe_stream_user", is_staff=True, is_superuser=True)
        UserContactInfo.objects.create(user=self.user, block_execution=True)
        self.system_settings(enable_deduplication=False)
        self.system_settings(enable_product_grade=False)

        product_type = Product_Type.objects.create(name="Dedupe Stream PT")
        product = Product.objects.create(name="Dedupe Stream Product", description="Test", prod_type=product_type)
        self.engagement = Engagement.objects.create(
            name="Dedupe Stream Engagement",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.test_type = Test_Type.objects.get_or_create(name="Manual Test")[0]
        self.other_test_type = Test_Type.objects.get_or_create(name="Dedupe Stream Other Tool")[0]
        self.existing_test = self._create_test(self.test_type)
        self.other_tool_test = self._create_test(self.other_test_type)
        self.new_test = self._create_test(self.test_type)

        # Existing findings with deliberate uid/hash collisions: several share HASH_A, some share
        # a uid, one carries both a colliding uid and a colliding hash, one is already a duplicate
        # (excluded in deduplication mode, kept for reimport), one has the right uid but a
        # different tool (a uid only matches within its own test type), and one is unrelated.
        self.hash_a_1 = self._create_finding(self.existing_test, "hash a 1", HASH_A)
        self.hash_a_2 = self._create_finding(self.existing_test, "hash a 2", HASH_A)
        self.hash_a_uid_1 = self._create_finding(self.existing_test, "hash a + uid 1", HASH_A, unique_id="uid-1")
        self.uid_1 = self._create_finding(self.existing_test, "uid 1", HASH_UNRELATED, unique_id="uid-1")
        self.uid_2 = self._create_finding(self.existing_test, "uid 2", None, unique_id="uid-2")
        self.hash_b = self._create_finding(self.existing_test, "hash b", HASH_B)
        self.duplicate_hash_a = self._create_finding(self.existing_test, "dup hash a", HASH_A, duplicate=True)
        self.uid_1_other_tool = self._create_finding(self.other_tool_test, "uid 1 other tool", None, unique_id="uid-1")
        self.unrelated = self._create_finding(self.existing_test, "unrelated", HASH_UNRELATED)

        self.batch = [
            self._create_finding(self.new_test, "new hash a", HASH_A),
            self._create_finding(self.new_test, "new uid 1", None, unique_id="uid-1"),
            self._create_finding(self.new_test, "new hash b + uid 2", HASH_B, unique_id="uid-2"),
        ]

    def _create_test(self, test_type):
        return Test.objects.create(
            engagement=self.engagement,
            test_type=test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    def _create_finding(self, test, title, hash_code, *, unique_id=None, duplicate=False):
        finding = Finding.objects.create(
            test=test,
            title=title,
            severity="High",
            description="Test",
            mitigation="Test",
            impact="Test",
            reporter=self.user,
            active=True,
            verified=True,
        )
        # Assigning after create keeps Finding.save() from recomputing the hash.
        Finding.objects.filter(pk=finding.pk).update(
            hash_code=hash_code,
            unique_id_from_tool=unique_id,
            duplicate=duplicate,
        )
        finding.refresh_from_db()
        return finding

    def test_candidates_match_the_unchunked_evaluation(self):
        for mode in ("deduplication", "reimport"):
            test = self.new_test if mode == "deduplication" else self.existing_test
            expected_by_uid, expected_by_hash = _unchunked_reference(test, self.batch, mode)
            self.assertTrue(expected_by_hash, f"fixture produced no hash candidates in {mode} mode")
            for chunk_size in (1, 2, 3, 1000):
                with self.subTest(mode=mode, chunk_size=chunk_size), mock.patch.object(
                    deduplication, "DEDUPE_CANDIDATE_CHUNK_SIZE", chunk_size,
                ):
                    by_uid, by_hash = find_candidates_for_deduplication_uid_or_hash(test, self.batch, mode=mode)
                    self.assertEqual(_ids(by_uid), _ids(expected_by_uid))
                    self.assertEqual(_ids(by_hash), _ids(expected_by_hash))

    def test_collisions_resolve_to_the_expected_candidates(self):
        """Spell the deduplication-mode result out, so the reference helper cannot drift unnoticed."""
        # The product scope includes the batch's own test, so each new finding is its own
        # candidate too; the matcher's older-than check drops those later.
        new_hash_a, new_uid_1, new_hash_b_uid_2 = self.batch
        by_uid, by_hash = find_candidates_for_deduplication_uid_or_hash(self.new_test, self.batch)
        self.assertEqual(
            _ids(by_hash),
            {
                HASH_A: [self.hash_a_1.id, self.hash_a_2.id, self.hash_a_uid_1.id, new_hash_a.id],
                HASH_B: [self.hash_b.id, new_hash_b_uid_2.id],
                HASH_UNRELATED: [self.uid_1.id],
            },
        )
        # The duplicate is excluded, the other tool's uid never matches, and the unrelated
        # finding is absent from both maps.
        self.assertEqual(
            _ids(by_uid),
            {
                "uid-1": [self.hash_a_uid_1.id, self.uid_1.id, new_uid_1.id],
                "uid-2": [self.uid_2.id, new_hash_b_uid_2.id],
            },
        )
        # The candidates are still full model instances with the prefetched relations the
        # matcher walks, not bare ids.
        candidate = by_hash[HASH_A][0]
        self.assertIsInstance(candidate, Finding)
        self.assertIn("finding_cwe_set", getattr(candidate, "_prefetched_objects_cache", {}))

    def test_candidate_queryset_is_streamed_not_materialised(self):
        real_iterator = QuerySet.iterator
        iterator_calls = []

        def recording_iterator(queryset, *args, **kwargs):
            if queryset.model is Finding:
                iterator_calls.append(kwargs.get("chunk_size", args[0] if args else None))
            return real_iterator(queryset, *args, **kwargs)

        real_fetch_all = QuerySet._fetch_all
        materialised = []

        def recording_fetch_all(queryset):
            if queryset.model is Finding:
                materialised.append(str(queryset.query))
            return real_fetch_all(queryset)

        with (
            mock.patch.object(deduplication, "DEDUPE_CANDIDATE_CHUNK_SIZE", 2),
            mock.patch.object(QuerySet, "iterator", recording_iterator),
            mock.patch.object(QuerySet, "_fetch_all", recording_fetch_all),
        ):
            _by_uid, by_hash = find_candidates_for_deduplication_uid_or_hash(self.new_test, self.batch)

        self.assertTrue(by_hash)
        self.assertEqual(iterator_calls, [2], "the candidate queryset must be walked with iterator(chunk_size=...)")
        self.assertEqual(materialised, [], f"the Finding candidate queryset was materialised whole: {materialised}")

    def test_prefetches_run_per_chunk(self):
        """A smaller chunk means more, smaller prefetch queries: no single prefetch spans every candidate."""

        def query_count(chunk_size):
            with (
                mock.patch.object(deduplication, "DEDUPE_CANDIDATE_CHUNK_SIZE", chunk_size),
                CaptureQueriesContext(connection) as ctx,
            ):
                find_candidates_for_deduplication_uid_or_hash(self.new_test, self.batch)
            return len(ctx.captured_queries)

        self.assertGreater(query_count(1), query_count(1000))

    def test_candidates_share_one_test_engagement_and_test_type_instance(self):
        _by_uid, by_hash = find_candidates_for_deduplication_uid_or_hash(self.new_test, self.batch)
        existing = [c for c in by_hash[HASH_A] if c.test_id == self.existing_test.id]
        self.assertGreater(len(existing), 1)
        self.assertEqual(len({id(c.test) for c in existing}), 1, "same-test candidates should share one Test")

        everyone = [c for bucket in by_hash.values() for c in bucket]
        self.assertEqual(len({id(c.test.engagement) for c in everyone}), 1, "one engagement, one instance")
        self.assertEqual(len({id(c.test.test_type) for c in everyone}), 1, "one test type, one instance")
        for candidate in everyone:
            # Sharing drops duplicate copies only: every relation still points at the right row.
            self.assertEqual(candidate.test.pk, candidate.test_id)
            self.assertEqual(candidate.test.engagement.pk, self.engagement.pk)
            self.assertEqual(candidate.test.test_type.pk, self.test_type.pk)
            self.assertEqual(candidate.test.engagement.deduplication_on_engagement, self.engagement.deduplication_on_engagement)
