import base64
import logging

from django.db import connection
from django.test import override_settings
from django.utils import timezone

from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import (
    BurpRawRequestResponse,
    Development_Environment,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test_Import_Finding_Action,
    User,
)
from dojo.vulnerability.models import FindingVulnerabilityReference

from .dojo_test_case import DojoTestCase, get_unit_tests_scans_path

logger = logging.getLogger(__name__)

SCAN_TYPE = "Acunetix Scan"
SCAN_FILE = "many_findings.xml"
REQUEST = b"GET / HTTP/1.1"
RESPONSE = b"HTTP/1.1 200 OK"


class TestImportersDeletedFindingChildRows(DojoTestCase):

    """
    Regression: child rows buffered for a finding deleted mid-batch broke the whole import.

    Vulnerability ids and Burp request/response pairs are not written as each finding is
    processed. They are buffered and bulk-inserted at the batch boundary, so a finding is
    live in the buffer for as long as it takes to process the rest of its batch (up to a
    thousand findings). A finding row can go away inside that window -- the excess
    duplicate cleanup task deletes findings, and so does a user deleting findings or a
    delete cascading from a test or engagement -- and the buffered row then points at a
    primary key that is no longer in dojo_finding.

    Django declares its foreign keys DEFERRABLE INITIALLY DEFERRED, so that insert does
    not fail where it is issued: PostgreSQL raises it at COMMIT, past every handler that
    knew what the import was doing. The reported symptom is an import that dies with
    'insert or update on table "dojo_findingvulnerabilityreference" violates foreign key
    constraint ... Key (finding_id)=(...) is not present in table "dojo_finding"' and takes
    the rest of the batch -- findings that were perfectly fine -- down with it.

    connection.check_constraints() below is the check PostgreSQL runs at COMMIT in
    production; the test transaction never commits, so the violation has to be asked for.
    """

    def setUp(self):
        super().setUp()
        self.user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="deleted_finding_child_rows")
        self.environment, _ = Development_Environment.objects.get_or_create(name="Development")
        self.product, _ = Product.objects.get_or_create(
            name="TestImportersDeletedFindingChildRows",
            description="Test",
            prod_type=product_type,
        )
        self.engagement, _ = Engagement.objects.get_or_create(
            name="Deleted Finding Child Rows",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        with (get_unit_tests_scans_path("acunetix") / SCAN_FILE).open(encoding="utf-8") as scan:
            self.test, _, len_new_findings, _, _, _, _ = self._importer().process_scan(scan)
        self.assertEqual(4, len_new_findings)
        self.findings = list(Finding.objects.filter(test=self.test).order_by("id"))
        self.assertGreaterEqual(len(self.findings), 2)

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

    def _importer(self):
        return DefaultImporter(close_old_findings=False, **self._options(engagement=self.engagement))

    def _reimporter(self):
        return DefaultReImporter(close_old_findings=False, **self._options(test=self.test))

    def _buffer_vulnerability_ids(self, importer, finding, vulnerability_ids):
        """Buffer vulnerability ids for `finding` the way the import path does."""
        finding.unsaved_vulnerability_ids = list(vulnerability_ids)
        importer.store_vulnerability_ids(finding)

    def _buffer_request_response(self, importer, finding):
        """Buffer a Burp request/response pair for `finding` the way a dynamic parser does."""
        importer.pending_burp_rr.append(BurpRawRequestResponse(
            finding=finding,
            burpRequestBase64=base64.b64encode(REQUEST),
            burpResponseBase64=base64.b64encode(RESPONSE),
        ))

    def _written_vulnerability_ids(self, finding_pk):
        """The vulnerability id strings actually persisted for `finding_pk`, in reference order."""
        return [
            ref.vulnerability.vulnerability_id
            for ref in FindingVulnerabilityReference.objects.filter(
                finding_id=finding_pk,
            ).select_related("vulnerability").order_by("order")
        ]

    def _buffered_request_response_count(self, finding):
        """
        Count only the pairs this test buffered.

        The scan the fixture imports brings its own request/response pairs, so the guard
        has to be judged on the rows under test rather than on the finding's total.
        """
        return BurpRawRequestResponse.objects.filter(
            finding_id=finding.pk,
            burpRequestBase64=base64.b64encode(REQUEST),
        ).count()

    def test_flush_vulnerability_ids_skips_a_finding_deleted_after_buffering(self):
        """The deleted finding's rows are dropped; the rest of the batch is still written."""
        importer = self._importer()
        deleted_finding, surviving_finding = self.findings[0], self.findings[1]
        self._buffer_vulnerability_ids(importer, deleted_finding, ["CVE-2020-1234"])
        self._buffer_vulnerability_ids(importer, surviving_finding, ["CVE-2020-5678"])
        deleted_pk = deleted_finding.pk
        Finding.objects.filter(pk=deleted_pk).delete()

        importer.flush_vulnerability_ids()
        connection.check_constraints()

        self.assertEqual(
            [],
            self._written_vulnerability_ids(deleted_pk),
            msg=f"no vulnerability id may be written for deleted finding {deleted_pk}",
        )
        self.assertEqual(
            ["CVE-2020-5678"],
            self._written_vulnerability_ids(surviving_finding.pk),
            msg="the surviving finding's vulnerability id must still be written",
        )

    def test_flush_vulnerability_ids_writes_everything_when_nothing_was_deleted(self):
        """Control case: the guard must not drop rows on a run where every finding is still there."""
        importer = self._importer()
        for index, finding in enumerate(self.findings):
            self._buffer_vulnerability_ids(importer, finding, [f"CVE-2020-100{index}"])

        importer.flush_vulnerability_ids()
        connection.check_constraints()

        for index, finding in enumerate(self.findings):
            self.assertEqual(
                [f"CVE-2020-100{index}"],
                self._written_vulnerability_ids(finding.pk),
                msg=f"finding {finding.pk} lost its vulnerability id",
            )

    def test_flush_vulnerability_ids_clears_the_buffer_after_dropping_rows(self):
        """A dropped row must not be retried by the next batch's flush."""
        importer = self._importer()
        deleted_finding = self.findings[0]
        self._buffer_vulnerability_ids(importer, deleted_finding, ["CVE-2020-1234"])
        deleted_pk = deleted_finding.pk
        Finding.objects.filter(pk=deleted_pk).delete()

        importer.flush_vulnerability_ids()
        self.assertEqual([], importer.vulnerability_id_manager.pending)
        self.assertEqual([], importer.pending_cwes)

        # A second flush stands in for the next batch boundary of the same import.
        importer.flush_vulnerability_ids()
        connection.check_constraints()
        self.assertEqual([], self._written_vulnerability_ids(deleted_pk))

    def test_reimport_reconcile_and_flush_survives_a_finding_deleted_mid_batch(self):
        """
        The reported path: reimport reconciles an existing finding's vulnerability ids.

        reconcile_vulnerability_ids() buffers a delete plus the replacement rows for a
        finding that already exists, and the flush happens at the batch boundary. The
        finding is deleted in between, which is where the dangling insert came from.
        """
        reimporter = self._reimporter()
        deleted_finding, surviving_finding = self.findings[0], self.findings[1]
        for finding, vulnerability_id in (
            (deleted_finding, "CVE-2021-1111"),
            (surviving_finding, "CVE-2021-2222"),
        ):
            finding.unsaved_vulnerability_ids = [vulnerability_id]
            reimporter.reconcile_vulnerability_ids(finding)
        deleted_pk = deleted_finding.pk
        Finding.objects.filter(pk=deleted_pk).delete()

        reimporter.flush_vulnerability_ids()
        connection.check_constraints()

        self.assertEqual(
            [],
            self._written_vulnerability_ids(deleted_pk),
            msg=f"no vulnerability id may be written for deleted finding {deleted_pk}",
        )
        self.assertEqual(
            ["CVE-2021-2222"],
            self._written_vulnerability_ids(surviving_finding.pk),
            msg="the surviving finding's reconciled vulnerability id must still be written",
        )

    def test_flush_burp_request_response_skips_a_finding_deleted_after_buffering(self):
        """Request/response pairs are buffered and flushed the same way, so they need the same guard."""
        importer = self._importer()
        deleted_finding, surviving_finding = self.findings[0], self.findings[1]
        self._buffer_request_response(importer, deleted_finding)
        self._buffer_request_response(importer, surviving_finding)
        deleted_pk = deleted_finding.pk
        Finding.objects.filter(pk=deleted_pk).delete()

        importer.flush_burp_request_response()
        connection.check_constraints()

        self.assertFalse(
            BurpRawRequestResponse.objects.filter(finding_id=deleted_pk).exists(),
            msg=f"no request/response pair may be written for deleted finding {deleted_pk}",
        )
        self.assertEqual(
            1,
            self._buffered_request_response_count(surviving_finding),
            msg="the surviving finding's request/response pair must still be written",
        )

    def test_flush_burp_request_response_writes_everything_when_nothing_was_deleted(self):
        """Control case for the request/response buffer."""
        importer = self._importer()
        for finding in self.findings:
            self._buffer_request_response(importer, finding)

        importer.flush_burp_request_response()
        connection.check_constraints()

        for finding in self.findings:
            self.assertEqual(
                1,
                self._buffered_request_response_count(finding),
                msg=f"finding {finding.pk} lost its request/response pair",
            )

    @override_settings(TRACK_IMPORT_HISTORY=True)
    def test_update_import_history_skips_a_finding_deleted_during_the_import(self):
        """
        The import-history records go through the same existence lookup as the buffers.

        Its own test class (UpdateImportHistoryTests) needs TransactionTestCase for the
        IntegrityError fallback and is skipped, so the shared pre-check is asserted here.
        """
        importer = self._importer()
        importer.test = self.test
        deleted_finding, *surviving_findings = self.findings
        deleted_pk = deleted_finding.pk
        Finding.objects.filter(pk=deleted_pk).delete()

        test_import = importer.update_import_history(
            new_findings=[finding.pk for finding in self.findings],
        )
        connection.check_constraints()

        recorded_finding_ids = set(
            Test_Import_Finding_Action.objects.filter(
                test_import=test_import,
            ).values_list("finding_id", flat=True),
        )
        self.assertNotIn(
            deleted_pk,
            recorded_finding_ids,
            msg=f"no history record may be written for deleted finding {deleted_pk}",
        )
        self.assertEqual(
            {finding.pk for finding in surviving_findings},
            recorded_finding_ids,
            msg="every surviving finding must still get its history record",
        )


class TestReconcileBeforeFindingIsWritten(DojoTestCase):

    """
    A finding's child rows must be reconcilable before the finding itself is written.

    Vulnerability ids and CWEs are already buffered and flushed at the batch boundary rather
    than written per finding. Reconciling them, though, read the finding's existing rows back
    through a reverse relation, and Django refuses that on an instance with no primary key
    ("instance needs to have a primary key value before this relationship can be used"). So an
    importer that buffers the finding inserts themselves -- writing them in bulk at the same
    batch boundary -- could not reconcile at all.

    For a finding with no row there is nothing to read: no persisted vulnerability ids, no
    persisted CWEs, and nothing to delete. Treating the existing set as empty is exact, not a
    workaround. Every path here already runs today with a saved finding; these tests cover the
    case that previously raised.
    """

    def setUp(self):
        super().setUp()
        self.user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="reconcile_before_write")
        self.environment, _ = Development_Environment.objects.get_or_create(name="Development")
        self.product, _ = Product.objects.get_or_create(
            name="TestReconcileBeforeFindingIsWritten",
            description="Test",
            prod_type=product_type,
        )
        self.engagement, _ = Engagement.objects.get_or_create(
            name="Reconcile Before Write",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        with (get_unit_tests_scans_path("acunetix") / SCAN_FILE).open(encoding="utf-8") as scan:
            self.test, _, _, _, _, _, _ = DefaultImporter(
                close_old_findings=False,
                user=self.user,
                lead=self.user,
                scan_date=None,
                environment=self.environment,
                active=True,
                verified=False,
                scan_type=SCAN_TYPE,
                engagement=self.engagement,
            ).process_scan(scan)

    def _reimporter(self):
        return DefaultReImporter(
            close_old_findings=False,
            user=self.user,
            lead=self.user,
            scan_date=None,
            environment=self.environment,
            active=True,
            verified=False,
            scan_type=SCAN_TYPE,
            test=self.test,
        )

    def _unsaved_finding(self, title="Buffered finding"):
        return Finding(test=self.test, title=title, severity="Medium", reporter=self.user)

    def test_reconcile_vulnerability_ids_accepts_an_unsaved_finding(self):
        reimporter = self._reimporter()
        finding = self._unsaved_finding()
        finding.unsaved_vulnerability_ids = ["CVE-2026-0001"]

        self.assertIsNone(finding.pk, "premise: the finding under test must be unsaved")
        reimporter.reconcile_vulnerability_ids(finding)

        self.assertEqual("CVE-2026-0001", finding.cve)
        self.assertIsNone(finding.pk, "reconciling must not write the finding")

    def test_buffered_vulnerability_ids_are_written_once_the_finding_is(self):
        """The sequence a batched writer uses: reconcile while unsaved, write, then flush."""
        reimporter = self._reimporter()
        finding = self._unsaved_finding("Buffered then written")
        finding.unsaved_vulnerability_ids = ["CVE-2026-0002"]

        reimporter.reconcile_vulnerability_ids(finding)
        # The buffered insert happens here, exactly as a batched writer would flush it.
        finding.save()
        reimporter.flush_vulnerability_ids()

        self.assertEqual(
            ["CVE-2026-0002"],
            [
                ref.vulnerability.vulnerability_id
                for ref in FindingVulnerabilityReference.objects.filter(
                    finding_id=finding.pk,
                ).select_related("vulnerability").order_by("order")
            ],
        )

    def test_reconcile_cwes_accepts_an_unsaved_finding_and_queues_no_delete(self):
        reimporter = self._reimporter()
        finding = self._unsaved_finding("Buffered with cwes")
        finding.cwe = 79

        self.assertIsNone(finding.pk, "premise: the finding under test must be unsaved")
        reimporter.reconcile_cwes(finding)

        # Stored as canonical CWE-<n> labels, not the raw Finding.cwe integer.
        self.assertEqual({"CWE-79"}, {row.cwe for row in reimporter.pending_cwes})
        self.assertEqual(
            [],
            reimporter.pending_cwe_deletes,
            msg="a finding with no row has no CWE rows to delete, so nothing may be queued",
        )

    def test_a_changed_cve_does_not_write_an_unsaved_finding(self):
        """
        finding_post_processing() saves on a cve change to update an existing row.

        A buffered finding has no row to update, and saving here would insert it early --
        defeating the buffering by splitting one batched INSERT into per-finding ones.
        """
        reimporter = self._reimporter()
        from_report = self._unsaved_finding("Report side")
        from_report.unsaved_vulnerability_ids = ["CVE-2026-0003"]
        finding = self._unsaved_finding("Buffered cve change")

        finding_count_before = Finding.objects.count()
        reimporter.finding_post_processing(
            finding,
            from_report,
            is_matched_finding=False,
            tag_accumulator=[],
        )

        self.assertEqual("CVE-2026-0003", finding.cve, "premise: the cve must actually have changed")
        self.assertIsNone(finding.pk, "the buffered finding must not have been written")
        self.assertEqual(finding_count_before, Finding.objects.count())
