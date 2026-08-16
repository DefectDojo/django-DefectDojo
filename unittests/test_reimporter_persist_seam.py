from django.utils import timezone

from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import Development_Environment, Engagement, Finding, Product, Product_Type, User

from .dojo_test_case import DojoTestCase, get_unit_tests_scans_path

SCAN_TYPE = "Acunetix Scan"
SCAN_FILE = "many_findings.xml"


class BufferingReImporter(DefaultReImporter):

    """
    A downstream edition that defers new-finding writes to the batch boundary.

    This is the shape persist_new_finding() exists for, written out in full so the seam is
    tested by a real user of it rather than by a mock. It buffers instead of writing, and
    flushes the buffer at the start of the batch flush -- before anything in that block
    (locations, vulnerability ids, tags, post-processing dispatch) reads a primary key.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.buffered: list[Finding] = []
        self.flush_calls = 0
        self.max_buffer_seen = 0

    def persist_new_finding(self, finding: Finding) -> None:
        self.buffered.append(finding)
        self.max_buffer_seen = max(self.max_buffer_seen, len(self.buffered))

    def _flush_post_processing_batch(self, *args, **kwargs) -> None:
        self.flush_calls += 1
        for finding in self.buffered:
            finding.save_no_options()
        self.buffered.clear()
        super()._flush_post_processing_batch(*args, **kwargs)


class TestNewFindingPersistSeam(DojoTestCase):

    """
    persist_new_finding() must let a downstream edition defer the write.

    The importer writes each unmatched finding as it is processed. An edition that wants to
    write them in bulk cannot do that without a seam: overriding
    process_finding_that_was_not_matched() means copying its whole body, which then drifts
    from upstream. This pins that overriding the one call is sufficient, and that the caller's
    remaining work stays safe on a finding that has not been written yet.
    """

    def setUp(self):
        super().setUp()
        self.user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="persist_seam")
        self.environment, _ = Development_Environment.objects.get_or_create(name="Development")
        self.product, _ = Product.objects.get_or_create(
            name="TestNewFindingPersistSeam",
            description="Test",
            prod_type=product_type,
        )
        self.engagement, _ = Engagement.objects.get_or_create(
            name="Persist Seam",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    def _options(self, **overrides):
        options = {
            "user": self.user,
            "lead": self.user,
            "scan_date": None,
            "environment": self.environment,
            "active": True,
            "verified": False,
            "scan_type": SCAN_TYPE,
        }
        options.update(overrides)
        return options

    def _empty_test(self, name):
        """A Test with no findings, created by importing into a fresh engagement."""
        engagement = Engagement.objects.create(
            name=name,
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        with (get_unit_tests_scans_path("acunetix") / "one_finding.xml").open(encoding="utf-8") as scan:
            test, _, _, _, _, _, _ = DefaultImporter(
                close_old_findings=False, **self._options(engagement=engagement),
            ).process_scan(scan)
        Finding.objects.filter(test=test).delete()
        return test

    def _reimport(self, test, importer_class):
        with (get_unit_tests_scans_path("acunetix") / SCAN_FILE).open(encoding="utf-8") as scan:
            importer = importer_class(close_old_findings=False, **self._options(test=test))
            importer.process_scan(scan)
        return importer

    @staticmethod
    def _comparable(test):
        """Findings as comparable tuples -- ids differ between runs, so they are excluded."""
        return sorted(
            (f.title, f.severity, f.cve, f.component_name, f.component_version, f.active, f.verified)
            for f in Finding.objects.filter(test=test)
        )

    def test_the_default_still_writes_each_finding_as_it_is_processed(self):
        """The seam must not change stock behaviour."""
        test = self._empty_test("seam-default")
        self._reimport(test, DefaultReImporter)
        self.assertGreater(Finding.objects.filter(test=test).count(), 0)

    def test_an_override_can_defer_the_write_to_the_batch_boundary(self):
        test = self._empty_test("seam-buffered")

        importer = self._reimport(test, BufferingReImporter)

        self.assertGreater(
            importer.max_buffer_seen,
            0,
            msg="premise: the override must actually have buffered something, or this proves nothing",
        )
        self.assertEqual(importer.buffered, [], "the buffer must be drained by the final flush")
        self.assertGreater(Finding.objects.filter(test=test).count(), 0)

    def test_deferring_the_write_produces_the_same_findings(self):
        """The point of the seam: same result, different write timing."""
        stock_test = self._empty_test("seam-equiv-stock")
        buffered_test = self._empty_test("seam-equiv-buffered")

        self._reimport(stock_test, DefaultReImporter)
        self._reimport(buffered_test, BufferingReImporter)

        stock = self._comparable(stock_test)
        buffered = self._comparable(buffered_test)
        self.assertEqual(len(stock), len(buffered))
        self.assertEqual(stock, buffered)

    def test_child_rows_still_land_for_a_deferred_finding(self):
        """
        The flush block writes locations, vulnerability ids and tags off the finding.

        Those all need a primary key, which is why the buffer drains at the *start* of the
        flush. If that ordering broke, the findings would exist with no vulnerability ids.
        """
        stock_test = self._empty_test("seam-children-stock")
        buffered_test = self._empty_test("seam-children-buffered")

        self._reimport(stock_test, DefaultReImporter)
        self._reimport(buffered_test, BufferingReImporter)

        def cve_set(test):
            return {f.cve for f in Finding.objects.filter(test=test) if f.cve}

        self.assertEqual(cve_set(stock_test), cve_set(buffered_test))

    def test_new_items_holds_real_ids_even_for_a_deferred_write(self):
        """
        new_items must report the finding's real id, not a premature read of it.

        process_finding_that_was_not_matched() queues each new finding; persist_new_findings()
        writes the queued batch and hands the same objects back, written or not depending on
        persist_new_finding(). A caller that reads finding.id right there -- rather than after
        the batch's write is guaranteed to have happened -- captures None for a deferred
        edition. That silently breaks any sync-wide bookkeeping keyed on new_items (for
        example a chunked importer's seen-id set), which then cannot recognize the finding by
        id and treats it as never having been reported.
        """
        test = self._empty_test("seam-ids-buffered")

        importer = self._reimport(test, BufferingReImporter)

        actual_ids = set(Finding.objects.filter(test=test).values_list("id", flat=True))
        self.assertNotIn(None, importer.new_items, "a deferred write must not leave None in new_items")
        self.assertEqual(set(importer.new_items), actual_ids)


class TestReimportMatchCandidateOrdering(DojoTestCase):

    """
    match_finding_to_candidate_reimport() returns matches in a priority order, and the caller
    reconciles matched_findings[0] while the remaining matches can be closed as stale. So the
    ORDER is behaviour, not an implementation detail: change which finding is first and a
    different existing finding gets reactivated while another is mitigated on the next reimport.

    These tests pin that order for every deduplication algorithm. The interesting one is the
    combined unique_id_from_tool_or_hash_code algorithm: it merges two separately-fetched
    candidate lists (hash matches, then uid matches), and a plain merge is not globally
    id-sorted -- an existing finding matched by hash would outrank a lower-id existing finding
    matched by uid, silently flipping which finding wins. The seam refactor originally dropped
    the historical id-sort to tolerate not-yet-persisted same-report candidates (pk=None); the
    fix restores a deterministic, pk-tolerant order instead of dropping ordering entirely.
    """

    def setUp(self):
        super().setUp()
        user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="match_order")
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        product, _ = Product.objects.get_or_create(
            name="TestReimportMatchCandidateOrdering",
            description="Test",
            prod_type=product_type,
        )
        engagement = Engagement.objects.create(
            name="Match Order",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        options = {
            "user": user,
            "lead": user,
            "scan_date": None,
            "environment": environment,
            "active": True,
            "verified": False,
            "scan_type": SCAN_TYPE,
        }
        with (get_unit_tests_scans_path("acunetix") / "one_finding.xml").open(encoding="utf-8") as scan:
            test, _, _, _, _, _, _ = DefaultImporter(
                close_old_findings=False, engagement=engagement, **options,
            ).process_scan(scan)
        self.importer = DefaultReImporter(close_old_findings=False, test=test, **options)

    @staticmethod
    def _incoming(*, hash_code=None, unique_id_from_tool=None, title="incoming", severity="High"):
        """An unsaved incoming finding carrying only the keys the matcher reads."""
        return Finding(title=title, severity=severity, hash_code=hash_code, unique_id_from_tool=unique_id_from_tool)

    def _match(self, algorithm, incoming, **candidate_dicts):
        self.importer.deduplication_algorithm = algorithm
        return self.importer.match_finding_to_candidate_reimport(incoming, **candidate_dicts)

    def test_combined_algorithm_orders_by_id_regardless_of_which_key_matched(self):
        """
        The regression this fix targets: an incoming finding matches a lower-id existing
        finding by unique_id and a higher-id one by hash. matched_findings[0] must be the
        lower-id finding, not whichever key was collected first.
        """
        by_hash = Finding(id=10)
        by_uid = Finding(id=5)
        result = self._match(
            "unique_id_from_tool_or_hash_code",
            self._incoming(hash_code="H", unique_id_from_tool="U"),
            candidates_by_hash={"H": [by_hash]},
            candidates_by_uid={"U": [by_uid]},
        )
        self.assertEqual([f.id for f in result], [5, 10])

    def test_combined_algorithm_dedupes_a_finding_matched_by_both_keys(self):
        """The same existing finding fetched under both keys is one object, returned once."""
        shared = Finding(id=7, hash_code="H", unique_id_from_tool="U")
        result = self._match(
            "unique_id_from_tool_or_hash_code",
            self._incoming(hash_code="H", unique_id_from_tool="U"),
            candidates_by_hash={"H": [shared]},
            candidates_by_uid={"U": [shared]},
        )
        self.assertEqual([f.id for f in result], [7])

    def test_combined_algorithm_keeps_an_unsaved_same_report_candidate_last(self):
        """
        A same-report duplicate queued earlier this batch has no pk yet. It must sort after
        every persisted candidate (and not raise, which a plain `.id` sort would).
        """
        existing = Finding(id=3)
        same_report = Finding(title="queued this batch")  # pk is None
        result = self._match(
            "unique_id_from_tool_or_hash_code",
            self._incoming(hash_code="H"),
            candidates_by_hash={"H": [same_report, existing]},
            candidates_by_uid=None,
        )
        self.assertEqual(result[0].pk, 3)
        self.assertIsNone(result[-1].pk)

    def test_single_key_algorithms_return_candidates_in_construction_order(self):
        """
        hash_code / unique_id_from_tool / legacy each read a single pre-ordered list
        (existing by id, then same-report appended) and must return it untouched -- including
        a trailing pk=None candidate.
        """
        ordered = [Finding(id=1), Finding(id=4), Finding(title="unsaved")]
        self.assertEqual(
            self._match("hash_code", self._incoming(hash_code="H"), candidates_by_hash={"H": ordered}),
            ordered,
        )
        self.assertEqual(
            self._match("unique_id_from_tool", self._incoming(unique_id_from_tool="U"), candidates_by_uid={"U": ordered}),
            ordered,
        )
        self.assertEqual(
            self._match("legacy", self._incoming(title="dup", severity="High"), candidates_by_key={("dup", "High"): ordered}),
            ordered,
        )
