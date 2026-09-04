"""
Tests for the injectable candidate scope in dojo.finding.deduplication.

The engine derives its own candidate scope from the incoming test: a finding
deduplicates against its own product, narrowed to one engagement by the
``deduplication_on_engagement`` flag. That derivation is the only scope an
installation can get, which is why ``build_candidate_scope_queryset`` now accepts a
``candidate_qs``, and why the winner rule accepts an ``ordering_key``.

Both are opt-in and default to the behaviour that was there before, so these tests
assert two things at once: that supplying them works, and that not supplying them
changes nothing.
"""

import logging

from django.utils import timezone

from dojo.finding.deduplication import (
    _dedupe_batch_hash_code,  # noqa: PLC2701
    build_candidate_scope_queryset,
    find_candidates_for_deduplication_hash,
    find_candidates_for_deduplication_legacy,
    find_candidates_for_deduplication_uid_or_hash,
    find_candidates_for_deduplication_unique_id,
    find_candidates_for_reimport_legacy,
    match_batch_hash_code,
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

SHARED_HASH = "a" * 64


class TestInjectableCandidateScope(DojoTestCase):

    """A caller may supply the candidate scope instead of letting the engine derive it."""

    def setUp(self):
        super().setUp()
        self.testuser = User.objects.create(
            username="dedupe_scope_user",
            is_staff=True,
            is_superuser=True,
        )
        UserContactInfo.objects.create(user=self.testuser, block_execution=True)
        self.system_settings(enable_deduplication=False)
        self.system_settings(enable_product_grade=False)

        self.product_type = Product_Type.objects.create(name="Dedupe Scope PT")
        self.test_type = Test_Type.objects.get_or_create(name="Manual Test")[0]
        # Two products, so the default scope cannot see across them.
        self.test_a = self._create_test("Dedupe Scope Product A", "Scope Engagement A")
        self.test_b = self._create_test("Dedupe Scope Product B", "Scope Engagement B")

    def _create_test(self, product_name, engagement_name):
        product = Product.objects.create(
            name=product_name,
            description="Test",
            prod_type=self.product_type,
        )
        engagement = Engagement.objects.create(
            name=engagement_name,
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        return Test.objects.create(
            engagement=engagement,
            test_type=self.test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    def _create_finding(self, test, title, hash_code=SHARED_HASH, *, unique_id=None, cwe=0):
        finding = Finding.objects.create(
            test=test,
            title=title,
            severity="High",
            description="Test",
            mitigation="Test",
            impact="Test",
            reporter=self.testuser,
            active=True,
            verified=True,
            cwe=cwe,
        )
        # Assigning after create keeps Finding.save() from recomputing it.
        Finding.objects.filter(pk=finding.pk).update(hash_code=hash_code, unique_id_from_tool=unique_id)
        finding.refresh_from_db()
        return finding

    # --- the default: unchanged ------------------------------------------

    def test_default_scope_is_the_product_and_excludes_other_products(self):
        """With no candidate_qs the scope is derived exactly as before."""
        mine = self._create_finding(self.test_a, "Scope default mine")
        theirs = self._create_finding(self.test_b, "Scope default theirs")

        scope = build_candidate_scope_queryset(self.test_a)
        scoped_ids = set(scope.values_list("id", flat=True))

        self.assertIn(mine.id, scoped_ids, "a finding in the test's own product is a candidate")
        self.assertNotIn(
            theirs.id, scoped_ids,
            "a finding in another product must not be a candidate under the derived scope",
        )

    def test_default_batch_dedupe_does_not_match_across_products(self):
        """The pre-existing behaviour this change must not disturb."""
        original = self._create_finding(self.test_b, "Cross-product original")
        newer = self._create_finding(self.test_a, "Cross-product newer")

        _dedupe_batch_hash_code([newer])

        newer.refresh_from_db()
        self.assertFalse(
            newer.duplicate,
            "identical hashes in two products must not deduplicate without an explicit scope",
        )
        self.assertNotEqual(newer.duplicate_finding_id, original.id)

    # --- the seam ---------------------------------------------------------

    def test_supplied_scope_replaces_the_derivation(self):
        """A supplied queryset is used as the candidate scope verbatim."""
        mine = self._create_finding(self.test_a, "Scope supplied mine")
        theirs = self._create_finding(self.test_b, "Scope supplied theirs")

        both_products = Finding.objects.filter(
            test__engagement__product__in=[
                self.test_a.engagement.product,
                self.test_b.engagement.product,
            ],
        )
        scope = build_candidate_scope_queryset(self.test_a, candidate_qs=both_products)
        scoped_ids = set(scope.values_list("id", flat=True))

        self.assertIn(mine.id, scoped_ids)
        self.assertIn(
            theirs.id, scoped_ids,
            "the supplied scope decides which findings are candidates, not the test's product",
        )

    def test_supplied_scope_matches_across_products(self):
        """Matching against a cross-product scope finds the other product's finding."""
        original = self._create_finding(self.test_b, "Cross-product scoped original")
        newer = self._create_finding(self.test_a, "Cross-product scoped newer")

        matches = match_batch_hash_code([newer], candidate_qs=Finding.objects.all())

        self.assertEqual(len(matches), 1, "the cross-product candidate should have matched")
        matched_new, matched_candidate = matches[0]
        self.assertEqual(matched_new.id, newer.id)
        self.assertEqual(matched_candidate.id, original.id)

    def test_supplied_scope_persists_the_cross_product_link(self):
        """The persisting path honours the supplied scope too, not just the match-only one."""
        original = self._create_finding(self.test_b, "Cross-product persisted original")
        newer = self._create_finding(self.test_a, "Cross-product persisted newer")

        _dedupe_batch_hash_code([newer], candidate_qs=Finding.objects.all())

        newer.refresh_from_db()
        self.assertTrue(newer.duplicate, "the finding should have been marked a duplicate")
        self.assertEqual(newer.duplicate_finding_id, original.id)

    def test_supplied_scope_still_prefers_the_older_candidate(self):
        """Widening the scope does not weaken the never-link-to-a-newer-finding rule."""
        # Creation order is the assertion here: the target must exist BEFORE the only
        # candidate, so the candidate is the newer of the two and cannot be its original.
        target = self._create_finding(self.test_a, "Ordering target")
        newer_candidate = self._create_finding(self.test_b, "Ordering newer candidate")

        matches = match_batch_hash_code([target], candidate_qs=Finding.objects.all())

        self.assertEqual(len(matches), 0, msg=(
            "the only candidate has a higher id than the target, so it is not a legal "
            f"original (candidate id={newer_candidate.id}, target id={target.id})"
        ))

    # --- ordering_key -----------------------------------------------------

    def test_ordering_key_selects_among_several_valid_candidates(self):
        """The preference order picks which older candidate becomes the original."""
        first = self._create_finding(self.test_b, "Ordering first original")
        second = self._create_finding(self.test_b, "Ordering second original")
        target = self._create_finding(self.test_a, "Ordering key target")

        # Default: oldest wins.
        default_matches = match_batch_hash_code([target], candidate_qs=Finding.objects.all())
        self.assertEqual(default_matches[0][1].id, first.id, "the default winner is the lowest id")

        # Prefer the second finding, then fall back to id order.
        preferred_matches = match_batch_hash_code(
            [target],
            candidate_qs=Finding.objects.all(),
            ordering_key=lambda candidate: (candidate.id != second.id, candidate.id),
        )
        self.assertEqual(
            preferred_matches[0][1].id, second.id,
            "the supplied ordering key should decide which of the valid candidates wins",
        )

    def test_ordering_key_cannot_promote_a_newer_candidate(self):
        """A preference order chooses among legal originals; it cannot create one."""
        older = self._create_finding(self.test_b, "Ordering older legal candidate")
        target = self._create_finding(self.test_a, "Ordering antisymmetry target")
        newer = self._create_finding(self.test_b, "Ordering newer illegal candidate")

        matches = match_batch_hash_code(
            [target],
            candidate_qs=Finding.objects.all(),
            # Ask for the newer finding first; the age guard must still reject it.
            ordering_key=lambda candidate: (candidate.id != newer.id, candidate.id),
        )

        self.assertEqual(len(matches), 1)
        self.assertEqual(
            matches[0][1].id, older.id,
            msg=(
                "an ordering key must not be able to make a newer finding the original "
                f"(newer id={newer.id}, target id={target.id})"
            ),
        )

    # --- every finder forwards it ----------------------------------------
    #
    # Five finders each build their own base queryset, so candidate_qs has to be threaded
    # through every one of them and any of them could drop it and stay green. The hash finder
    # is also reached through match_batch_hash_code above; it is called directly here so all
    # five state the property the same way.

    def test_supplied_scope_reaches_the_hash_finder(self):
        theirs = self._create_finding(self.test_b, "Hash scoped original")
        mine = self._create_finding(self.test_a, "Hash scoped newer")

        default = find_candidates_for_deduplication_hash(self.test_a, [mine])
        self.assertNotIn(theirs.id, [c.id for c in default.get(SHARED_HASH, [])])

        supplied = find_candidates_for_deduplication_hash(
            self.test_a, [mine], candidate_qs=Finding.objects.all(),
        )
        self.assertIn(
            theirs.id, [c.id for c in supplied.get(SHARED_HASH, [])],
            "the supplied scope did not reach the hash finder",
        )

    def test_supplied_scope_reaches_the_unique_id_finder(self):
        """
        Forwarding, not just the hash path.

        Each finder builds its own base queryset, so ``candidate_qs`` has to be threaded
        through every one of them. Covering only the hash finder would leave the unique-id and
        legacy paths free to drop the argument and stay green.
        """
        shared_uid = "SCOPE-UID-1"
        theirs = self._create_finding(self.test_b, "Uid scoped original", unique_id=shared_uid)
        mine = self._create_finding(self.test_a, "Uid scoped newer", unique_id=shared_uid)

        default = find_candidates_for_deduplication_unique_id(self.test_a, [mine])
        self.assertNotIn(
            theirs.id, [candidate.id for group in default.values() for candidate in group],
            "the derived scope must not reach the other product",
        )

        supplied = find_candidates_for_deduplication_unique_id(
            self.test_a, [mine], candidate_qs=Finding.objects.all(),
        )
        self.assertIn(
            theirs.id, [candidate.id for candidate in supplied.get(shared_uid, [])],
            "the supplied scope did not reach the unique-id finder",
        )

    def test_supplied_scope_reaches_the_legacy_finder(self):
        """Same forwarding property for the title/CWE finder, which returns two maps."""
        theirs = self._create_finding(self.test_b, "Legacy scoped finding", cwe=79)
        mine = self._create_finding(self.test_a, "Legacy scoped finding", cwe=79)
        # The map is keyed by the PERSISTED title, and Finding.save() titlecases it, so the
        # string passed to _create_finding is not the key. Read it back off the saved row.
        stored_title = mine.title

        default_by_title, default_by_cwe = find_candidates_for_deduplication_legacy(self.test_a, [mine])
        self.assertNotIn(
            theirs.id, [candidate.id for candidate in default_by_title.get(stored_title, [])],
            "the derived scope must not reach the other product",
        )
        self.assertNotIn(theirs.id, [candidate.id for candidate in default_by_cwe.get(79, [])])

        by_title, by_cwe = find_candidates_for_deduplication_legacy(
            self.test_a, [mine], candidate_qs=Finding.objects.all(),
        )
        self.assertIn(
            theirs.id, [candidate.id for candidate in by_title.get(stored_title, [])],
            "the supplied scope did not reach the legacy finder's title map",
        )
        self.assertIn(
            theirs.id, [candidate.id for candidate in by_cwe.get(79, [])],
            "the supplied scope did not reach the legacy finder's CWE map",
        )

    def test_supplied_scope_reaches_the_uid_or_hash_finder(self):
        """The combined finder builds its own base queryset too, and returns two maps."""
        shared_uid = "SCOPE-UID-2"
        theirs = self._create_finding(self.test_b, "Uid-or-hash scoped original", unique_id=shared_uid)
        mine = self._create_finding(self.test_a, "Uid-or-hash scoped newer", unique_id=shared_uid)

        default_by_uid, default_by_hash = find_candidates_for_deduplication_uid_or_hash(self.test_a, [mine])
        self.assertNotIn(theirs.id, [c.id for c in default_by_uid.get(shared_uid, [])])
        self.assertNotIn(theirs.id, [c.id for c in default_by_hash.get(SHARED_HASH, [])])

        by_uid, by_hash = find_candidates_for_deduplication_uid_or_hash(
            self.test_a, [mine], candidate_qs=Finding.objects.all(),
        )
        self.assertIn(
            theirs.id, [c.id for c in by_uid.get(shared_uid, [])],
            "the supplied scope did not reach the combined finder's unique-id map",
        )
        self.assertIn(
            theirs.id, [c.id for c in by_hash.get(SHARED_HASH, [])],
            "the supplied scope did not reach the combined finder's hash map",
        )

    def test_supplied_scope_reaches_the_legacy_reimport_finder(self):
        """Reimport normally scopes to the incoming test alone, which a supplied scope replaces."""
        shared_title = "Legacy reimport scoped finding"
        theirs = self._create_finding(self.test_b, shared_title)
        mine = self._create_finding(self.test_a, shared_title)
        key = (shared_title.lower(), "High")

        default = find_candidates_for_reimport_legacy(self.test_a, [mine])
        self.assertNotIn(
            theirs.id, [c.id for c in default.get(key, [])],
            "reimport's derived scope is the incoming test, so the other product must not appear",
        )

        supplied = find_candidates_for_reimport_legacy(
            self.test_a, [mine], candidate_qs=Finding.objects.all(),
        )
        self.assertIn(
            theirs.id, [c.id for c in supplied.get(key, [])],
            "the supplied scope did not reach the legacy reimport finder",
        )
