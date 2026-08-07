import logging
from unittest import mock

from django.core.exceptions import ValidationError
from django.utils import timezone

from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import (
    Development_Environment,
    Engagement,
    Product,
    Product_Type,
    Test,
    User,
)

from .dojo_test_case import DojoTestCase, get_unit_tests_scans_path

logger = logging.getLogger(__name__)

SCAN_TYPE = "Acunetix Scan"
SCAN_FILE = "one_finding.xml"


class TestImportersDeletedTarget(DojoTestCase):

    """
    Regression: an import target deleted while the scan was being processed was re-created
    by the importer's closing write-back.

    Model.save() on an instance whose primary key is already set issues an UPDATE and
    falls back to an INSERT when that UPDATE matches no rows. The importer loads its Test
    and Engagement at the start of a run that can take minutes, so a delete landing
    mid-run turned the write-back into an INSERT of the deleted row from a stale in-memory
    copy. Either the row was silently resurrected, or -- when the parent went with it --
    the INSERT carried a dangling foreign key and the caller got an opaque 500 naming a
    PostgreSQL constraint instead of the reason the import failed.
    """

    def setUp(self):
        super().setUp()
        self.user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="deleted_target")
        self.environment, _ = Development_Environment.objects.get_or_create(name="Development")
        self.product, _ = Product.objects.get_or_create(
            name="TestImportersDeletedTarget",
            description="Test",
            prod_type=product_type,
        )
        self.engagement, _ = Engagement.objects.get_or_create(
            name="Deleted Target Engagement",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        with (get_unit_tests_scans_path("acunetix") / SCAN_FILE).open(encoding="utf-8") as scan:
            self.test, _, len_new_findings, _, _, _, _ = self._importer().process_scan(scan)
        self.assertEqual(1, len_new_findings)

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

    def _process_with_delete_mid_run(self, importer, delete, hook):
        """
        Run a scan through `importer`, with `delete` firing just before the write-back.

        `hook` is the last step the importer takes before it saves the test and its
        engagement, so its call site is the window a concurrent delete lands in:
        update_test_tags() on the reimport path, update_test_meta() on the import path.
        """
        with (
            (get_unit_tests_scans_path("acunetix") / SCAN_FILE).open(encoding="utf-8") as scan,
            mock.patch.object(importer, hook, side_effect=delete),
        ):
            return importer.process_scan(scan)

    def test_reimport_does_not_resurrect_a_test_deleted_mid_run(self):
        """A test deleted while its scan was processed must not be re-created by the write-back."""
        test_pk = self.test.pk

        with self.assertRaises(ValidationError) as caught:
            self._process_with_delete_mid_run(
                self._reimporter(),
                lambda: Test.objects.filter(pk=test_pk).delete(),
                "update_test_tags",
            )

        self.assertFalse(
            Test.objects.filter(pk=test_pk).exists(),
            msg=f"the deleted test (id {test_pk}) must not be re-inserted by the reimport write-back",
        )
        self.assertIn(
            "deleted while the scan was being processed",
            str(caught.exception),
            msg=f"the error must say the import target was deleted, got: {caught.exception}",
        )

    def test_reimport_reports_the_deleted_target_not_a_constraint_violation(self):
        """An engagement delete cascades to its tests; the caller gets the reason, not a constraint name."""
        test_pk = self.test.pk
        engagement_pk = self.engagement.pk

        with self.assertRaises(ValidationError) as caught:
            self._process_with_delete_mid_run(
                self._reimporter(),
                lambda: Engagement.objects.filter(pk=engagement_pk).delete(),
                "update_test_meta",
            )

        message = str(caught.exception)
        self.assertNotIn(
            "foreign key constraint",
            message,
            msg=f"the caller must not be handed a database constraint violation, got: {message}",
        )
        self.assertIn("deleted while the scan was being processed", message, msg=message)
        self.assertFalse(
            Test.objects.filter(pk=test_pk).exists(),
            msg=f"the cascaded test (id {test_pk}) must not be re-inserted with a dangling engagement",
        )

    def test_import_does_not_resurrect_a_test_deleted_mid_run(self):
        """The import path shares the write-back, so it must refuse the same re-insert."""
        importer = self._importer()
        deleted_pks = []

        def delete_the_new_test():
            deleted_pks.append(importer.test.pk)
            Test.objects.filter(pk=importer.test.pk).delete()

        with self.assertRaises(ValidationError):
            self._process_with_delete_mid_run(importer, delete_the_new_test, "update_test_meta")

        self.assertEqual(1, len(deleted_pks), msg="the delete hook must have run")
        self.assertFalse(
            Test.objects.filter(pk=deleted_pks[0]).exists(),
            msg=f"the deleted test (id {deleted_pks[0]}) must not be re-inserted by the import write-back",
        )

    def test_update_test_progress_does_not_resurrect_a_deleted_test(self):
        """The closing progress write is the last save of a run and must not re-create the row either."""
        test_pk = self.test.pk
        importer = self._reimporter()
        importer.test = self.test
        Test.objects.filter(pk=test_pk).delete()

        with self.assertRaises(ValidationError):
            importer.update_test_progress()

        self.assertFalse(
            Test.objects.filter(pk=test_pk).exists(),
            msg=f"the deleted test (id {test_pk}) must not be re-inserted by update_test_progress",
        )

    def test_deleted_engagement_is_not_resurrected(self):
        """The engagement half of the write-back is guarded the same way as the test."""
        engagement_pk = self.engagement.pk
        importer = self._reimporter()
        Engagement.objects.filter(pk=engagement_pk).delete()

        with self.assertRaises(ValidationError) as caught:
            importer.save_without_resurrecting(self.engagement)

        self.assertFalse(
            Engagement.objects.filter(pk=engagement_pk).exists(),
            msg=f"the deleted engagement (id {engagement_pk}) must not be re-inserted",
        )
        self.assertIn("deleted while the scan was being processed", str(caught.exception))

    def test_reimport_still_persists_the_write_back_when_nothing_was_deleted(self):
        """Control case: the guard must not change a run whose target is still there."""
        test_pk = self.test.pk

        with (get_unit_tests_scans_path("acunetix") / SCAN_FILE).open(encoding="utf-8") as scan:
            test, _, _, _, _, _, _ = self._reimporter().process_scan(scan)

        self.assertEqual(test_pk, test.pk)
        persisted = Test.objects.get(pk=test_pk)
        self.assertEqual(
            100, persisted.percent_complete,
            msg=f"expected percent_complete=100, persisted={persisted.percent_complete}",
        )
        self.assertTrue(Engagement.objects.filter(pk=self.engagement.pk).exists())
