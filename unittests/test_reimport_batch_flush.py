from unittest import mock

from django.utils import timezone

from dojo.finding import helper as finding_helper
from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import Development_Environment, Engagement, Finding, Product, Product_Type, User

from .dojo_test_case import DojoTestCase, get_unit_tests_scans_path

SCAN_TYPE = "Acunetix Scan"


class TestReimportFinalBatchFlush(DojoTestCase):

    """
    Regression: a reimport whose last finding matched an existing special-status finding
    silently dropped the whole trailing batch.

    The processing loop accumulates created/updated findings and dispatches
    post_process_findings_batch (deduplication, rules, issue updater, JIRA) plus parser and
    inherited tag application at batch boundaries. The boundary check lived inside the loop
    and was skipped by the matched branch's force_continue -- taken whenever the incoming
    finding matches an existing false positive / out of scope / risk accepted finding whose
    statuses agree. Findings are content-sorted before processing, so any report whose
    last-sorted finding took that path lost everything accumulated since the previous
    size-triggered flush: for reports smaller than IMPORT_REIMPORT_DEDUPE_BATCH_SIZE, the
    entire report skipped deduplication and tagging.

    The fix drains the accumulators once, unconditionally, after the loop.
    """

    def setUp(self):
        super().setUp()
        self.user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="reimport_batch_flush")
        self.environment, _ = Development_Environment.objects.get_or_create(name="Development")
        self.product, _ = Product.objects.get_or_create(
            name="TestReimportFinalBatchFlush",
            description="Test",
            prod_type=product_type,
        )
        self.engagement, _ = Engagement.objects.get_or_create(
            name="Reimport Final Batch Flush",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        with (get_unit_tests_scans_path("acunetix") / "one_finding.xml").open(encoding="utf-8") as scan:
            importer = DefaultImporter(close_old_findings=False, **self._options(engagement=self.engagement))
            self.test, _, len_new_findings, _, _, _, _ = importer.process_scan(scan)
        self.assertEqual(1, len_new_findings)
        self.existing = Finding.objects.get(test=self.test)

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

    def _reimporter(self):
        return DefaultReImporter(close_old_findings=False, **self._options(test=self.test))

    def _dispatched_finding_ids(self, dispatch_mock):
        ids = []
        for call in dispatch_mock.call_args_list:
            if call.args and call.args[0] is finding_helper.post_process_findings_batch:
                ids.extend(call.args[1])
        return ids

    def test_final_force_continue_still_dispatches_the_batch(self):
        # Make the existing finding special-status so a status-parity match force_continues.
        Finding.objects.filter(pk=self.existing.pk).update(false_p=True)
        self.existing.refresh_from_db()

        reimporter = self._reimporter()

        # An incoming finding with the same hash fields and the same statuses as the
        # existing false positive: matches by hash, then takes the special-status parity
        # path, which force_continues out of the loop iteration.
        parity = Finding(
            test=self.test,
            title=self.existing.title,
            description=self.existing.description,
            severity=self.existing.severity,
            false_p=True,
            active=True,
            verified=False,
        )
        parity_hash = reimporter.calculate_unsaved_finding_hash_code(parity)
        # Premise: the crafted finding really does hash-match the stored one.
        self.assertEqual(self.existing.hash_code, parity_hash)

        # A genuinely new finding that must sort BEFORE the parity finding, so the parity
        # match is the loop's final iteration. The reimporter sorts by a content key whose
        # first element is hash_code, so vary the description until the hash orders first.
        # SHA-256 is uniform; 200 attempts cannot realistically fail to find one.
        fresh = None
        for attempt in range(200):
            candidate = Finding(
                test=self.test,
                title="brand new finding from the reimport",
                description=f"created by the reimport under test, variant {attempt}",
                severity="High",
                active=True,
                verified=False,
            )
            if reimporter.calculate_unsaved_finding_hash_code(candidate) < parity_hash:
                fresh = candidate
                break
        self.assertIsNotNone(fresh, "could not construct a finding sorting before the parity match")

        with mock.patch("dojo.importers.default_reimporter.dojo_dispatch_task") as dispatch:
            new_items, _, _, _ = reimporter.process_findings([fresh, parity])

        # Premise: the parity finding matched instead of being created -- the test only
        # exercises the force_continue tail when exactly one new finding exists.
        self.assertEqual(2, Finding.objects.filter(test=self.test).count())
        self.assertIn(self.existing, reimporter.unchanged_items)
        self.assertEqual([fresh], new_items)
        self.assertIsNotNone(fresh.pk)

        # The regression: with the boundary check inside the loop, the force_continue on
        # the final iteration skipped it and this batch was never dispatched at all.
        self.assertEqual([fresh.pk], self._dispatched_finding_ids(dispatch))

    def test_empty_report_drain_is_harmless(self):
        # The post-loop drain is unconditional; an empty report must stay a no-op.
        reimporter = self._reimporter()
        with mock.patch("dojo.importers.default_reimporter.dojo_dispatch_task") as dispatch:
            new_items, reactivated, _to_mitigate, _ = reimporter.process_findings([])
        self.assertEqual([], new_items)
        self.assertEqual([], reactivated)
        self.assertEqual([], self._dispatched_finding_ids(dispatch))
