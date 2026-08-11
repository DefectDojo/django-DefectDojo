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
