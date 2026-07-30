import logging

from django.utils import timezone
from parameterized import parameterized

from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import Development_Environment, Engagement, Product, Product_Type, Test, User

from .dojo_test_case import DojoTestCase, get_unit_tests_scans_path

logger = logging.getLogger(__name__)


class TestImportObjectDeletedDuringScan(DojoTestCase):

    """
    Regression: an object deleted while its scan is processed must not be re-inserted.

    The importers hold the test (and through it the engagement) in memory for the whole
    run and persist the accumulated changes at the end. Model.save() on an instance whose
    row has been deleted in the meantime does not fail: the UPDATE matches no row and
    Django falls through to an INSERT. The deleted row is therefore recreated, which
    either resurrects a row whose children are gone, or violates a foreign key when the
    delete took the parent rows too (a reimport reported
    'insert or update on table "dojo_test" violates foreign key constraint
    dojo_test_engagement_id_...' with the engagement id missing from dojo_engagement).
    """

    def setUp(self):
        super().setUp()
        self.scan_type = "Acunetix Scan"
        self.user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="deleted_during_scan")
        self.environment, _ = Development_Environment.objects.get_or_create(name="Development")
        self.product, _ = Product.objects.get_or_create(
            name="TestImportObjectDeletedDuringScan",
            description="Test",
            prod_type=product_type,
        )
        self.engagement, _ = Engagement.objects.get_or_create(
            name="Object Deleted During Scan",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        with (get_unit_tests_scans_path("acunetix") / "many_findings.xml").open(encoding="utf-8") as scan:
            importer = DefaultImporter(
                close_old_findings=False,
                user=self.user,
                lead=self.user,
                scan_date=None,
                environment=self.environment,
                active=True,
                verified=False,
                engagement=self.engagement,
                scan_type=self.scan_type,
            )
            self.test, _, len_new_findings, _, _, _, _ = importer.process_scan(scan)
        self.assertEqual(4, len_new_findings)

    def _reimporter(self):
        return DefaultReImporter(
            test=self.test,
            user=self.user,
            lead=self.user,
            scan_date=None,
            environment=self.environment,
            active=True,
            verified=False,
            scan_type=self.scan_type,
            close_old_findings=True,
        )

    def _delete_test_row(self):
        Test.objects.filter(pk=self.test.pk).delete()

    def _delete_engagement_row(self):
        # Deleting the engagement cascades to its tests, exactly as deleting an engagement
        # or a product in the UI does while a scan is being processed.
        Engagement.objects.filter(pk=self.engagement.pk).delete()

    @parameterized.expand([
        ("test_deleted", "_delete_test_row"),
        ("engagement_deleted", "_delete_engagement_row"),
    ])
    def test_update_test_progress_refuses_to_recreate_deleted_test(self, scenario, delete_method):
        """The test row is gone: report that instead of inserting it again."""
        test_pk = self.test.pk
        getattr(self, delete_method)()

        with self.assertRaises(Test.DoesNotExist):
            self._reimporter().update_test_progress()

        self.assertFalse(
            Test.objects.filter(pk=test_pk).exists(),
            msg=f"{scenario}: test {test_pk} was deleted during the scan and must not be recreated",
        )

    def test_save_test_and_engagement_refuses_to_recreate_deleted_test(self):
        """
        The engagement is gone, and with it the test: the reported failure.

        Recreating the test here is what produced the foreign key violation on
        dojo_test.engagement_id, because the engagement the recreated row points at no
        longer exists either.
        """
        test_pk = self.test.pk
        engagement_pk = self.engagement.pk
        self._delete_engagement_row()

        with self.assertRaises(Test.DoesNotExist):
            self._reimporter().save_test_and_engagement()

        self.assertFalse(
            Test.objects.filter(pk=test_pk).exists(),
            msg=f"test {test_pk} was deleted during the scan and must not be recreated",
        )
        self.assertFalse(
            Engagement.objects.filter(pk=engagement_pk).exists(),
            msg=f"engagement {engagement_pk} was deleted during the scan and must not be recreated",
        )

    def test_save_test_and_engagement_persists_changes_when_both_still_exist(self):
        """Control case: the normal path still writes the pending changes."""
        reimporter = self._reimporter()
        reimporter.test.percent_complete = 42
        reimporter.test.engagement.name = "Object Deleted During Scan (updated)"

        reimporter.save_test_and_engagement()

        persisted_test = Test.objects.get(pk=self.test.pk)
        persisted_engagement = Engagement.objects.get(pk=self.engagement.pk)
        self.assertEqual(
            42, persisted_test.percent_complete,
            msg=f"expected percent_complete=42, persisted={persisted_test.percent_complete}",
        )
        self.assertEqual(
            "Object Deleted During Scan (updated)", persisted_engagement.name,
            msg=f"expected the engagement name to be saved, persisted={persisted_engagement.name}",
        )

    def test_update_test_progress_persists_percentage_when_test_still_exists(self):
        """Control case: the normal path still records the progress percentage."""
        self._reimporter().update_test_progress(percentage_value=75)

        persisted_test = Test.objects.get(pk=self.test.pk)
        self.assertEqual(
            75, persisted_test.percent_complete,
            msg=f"expected percent_complete=75, persisted={persisted_test.percent_complete}",
        )
