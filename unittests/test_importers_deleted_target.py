import logging
from datetime import timedelta
from unittest import mock

from django.core.exceptions import ValidationError
from django.db import DEFAULT_DB_ALIAS, IntegrityError, connections
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

    def _reimporter(self, **overrides):
        return DefaultReImporter(close_old_findings=False, **self._options(test=self.test, **overrides))

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

    def test_write_back_still_persists_every_field_it_sets(self):
        """
        The forced update writes the whole row, exactly as the plain save() it replaced did.

        Narrowing it to save(update_fields=...) would detect the vanished row the same way
        and write fewer columns, but would silently drop any field a later change starts
        setting before the write-back. This pins what the importer sets today to what
        actually lands in the database.
        """
        updated_before_reimport = Test.objects.values_list("updated", flat=True).get(pk=self.test.pk)
        reimporter = self._reimporter(
            version="1.2.3",
            build_id="build-42",
            branch_tag="release/1.2",
            commit_hash="deadbeef",
        )

        with (get_unit_tests_scans_path("acunetix") / SCAN_FILE).open(encoding="utf-8") as scan:
            reimporter.process_scan(scan)

        persisted = Test.objects.get(pk=self.test.pk)
        self.assertEqual("1.2.3", persisted.version)
        self.assertEqual("build-42", persisted.build_id)
        self.assertEqual("release/1.2", persisted.branch_tag)
        self.assertEqual("deadbeef", persisted.commit_hash)
        self.assertEqual(100, persisted.percent_complete)
        self.assertEqual(reimporter.scan_date, persisted.target_end)
        self.assertGreater(
            persisted.updated, updated_before_reimport,
            msg="the auto_now `updated` column must still be bumped by the write-back",
        )

    def test_unchanged_engagement_is_not_written_back(self):
        """
        The engagement is only worth saving when the run actually moved its target end.

        `update_timestamps()` touches the engagement for CI/CD engagements only, so for
        every other import the write-back was spending a full UPDATE, plus the SELECT its
        pre_save receiver issues, to store nothing.
        """
        reimporter = self._reimporter()

        with (
            (get_unit_tests_scans_path("acunetix") / SCAN_FILE).open(encoding="utf-8") as scan,
            mock.patch.object(
                reimporter,
                "save_without_resurrecting",
                wraps=reimporter.save_without_resurrecting,
            ) as write_back,
        ):
            reimporter.process_scan(scan)

        written_back = [call.args[0] for call in write_back.call_args_list]
        self.assertFalse(
            any(isinstance(instance, Engagement) for instance in written_back),
            msg=f"an unchanged engagement must not be written back, got: {written_back}",
        )
        self.assertFalse(reimporter.engagement_target_end_updated)

    def test_ci_cd_engagement_target_end_is_still_written_back(self):
        """The engagement save the importer does need: a CI/CD target end the scan pushes out."""
        Engagement.objects.filter(pk=self.engagement.pk).update(
            engagement_type="CI/CD",
            target_end=timezone.now().date() - timedelta(days=7),
        )
        # Re-fetch rather than refresh: the test caches its engagement, and the write-back
        # reads engagement_type off that cached copy.
        self.test = Test.objects.get(pk=self.test.pk)
        reimporter = self._reimporter()

        with (get_unit_tests_scans_path("acunetix") / SCAN_FILE).open(encoding="utf-8") as scan:
            reimporter.process_scan(scan)

        self.assertTrue(reimporter.engagement_target_end_updated)
        self.assertEqual(
            reimporter.scan_date.date(),
            Engagement.objects.values_list("target_end", flat=True).get(pk=self.engagement.pk),
        )

    def test_a_real_database_error_is_not_reported_as_a_deleted_target(self):
        """
        Only Django's "forced update did not affect any rows" means the target vanished.

        Every other DatabaseError is a genuine failure, and relabelling it as a delete that
        never happened would send whoever debugs it after the wrong thing.
        """
        importer = self._reimporter()

        with (
            mock.patch.object(Test, "save", side_effect=IntegrityError("null value in column violates not-null constraint")),
            self.assertRaises(IntegrityError),
        ):
            importer.save_without_resurrecting(self.test)

    def test_the_transaction_is_still_usable_after_a_vanished_target(self):
        """
        The caller has to be able to record why the import failed.

        Model.save_base wraps the write in mark_for_rollback_on_error, so a forced update
        that matches no rows leaves the transaction marked for rollback and turns the next
        query into a TransactionManagementError. The UPDATE itself succeeded -- it matched
        no rows -- so nothing needs rolling back and the mark is cleared.
        """
        test_pk = self.test.pk
        importer = self._reimporter()
        Test.objects.filter(pk=test_pk).delete()

        with self.assertRaises(ValidationError):
            importer.save_without_resurrecting(self.test)

        self.assertFalse(
            connections[DEFAULT_DB_ALIAS].needs_rollback,
            msg="the connection must not be left marked for rollback",
        )
        # The reads and writes a failure handler makes must both still go through.
        self.assertFalse(Test.objects.filter(pk=test_pk).exists())
        Engagement.objects.filter(pk=self.engagement.pk).update(description="recorded after the failure")
        self.assertEqual(
            "recorded after the failure",
            Engagement.objects.values_list("description", flat=True).get(pk=self.engagement.pk),
        )
