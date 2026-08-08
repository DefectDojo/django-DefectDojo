import logging

from django.utils import timezone

from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import (
    Development_Environment,
    Engagement,
    Product,
    Product_Type,
    User,
)

from .dojo_test_case import DojoTestCase, get_unit_tests_scans_path

logger = logging.getLogger(__name__)

SCAN_TYPE = "Acunetix Scan"
SCAN_FILE = "one_finding.xml"


class TestEngagementEmptyStatus(DojoTestCase):

    """
    Regression: an engagement holding a NULL/empty `status` could not be saved at all.

    `status` and `engagement_type` are declared ``null=True`` but were never given
    ``blank=True``, and Django counts ``None`` among a field's empty values. Since
    Engagement validates itself on every save, a row storing NULL in either column
    failed its own validation with "This field cannot be blank." -- the model rejecting
    a value its own column permits.

    Every (re)import writes its engagement back at the end of the run, so a single such
    row turned every scheduled scan ingest into that engagement into a hard failure, and
    the API surfaced it as a 400 rather than importing anything.
    """

    def setUp(self):
        super().setUp()
        self.user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="empty_status")
        self.environment, _ = Development_Environment.objects.get_or_create(name="Development")
        self.product, _ = Product.objects.get_or_create(
            name="TestEngagementEmptyStatus",
            description="Test",
            prod_type=product_type,
        )
        self.engagement, _ = Engagement.objects.get_or_create(
            name="Empty Status Engagement",
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

    def _store_empty(self, **columns):
        """Put empty values straight into the columns, bypassing model validation."""
        Engagement.objects.filter(pk=self.engagement.pk).update(**columns)
        self.engagement.refresh_from_db()

    def test_engagement_with_null_status_can_be_saved(self):
        """A stored NULL status must not make the row unsavable."""
        self._store_empty(status=None)

        self.engagement.save()

        self.assertEqual(
            "Not Started",
            Engagement.objects.get(pk=self.engagement.pk).status,
            msg="an empty status must be normalized to the field default on save",
        )

    def test_engagement_with_blank_status_can_be_saved(self):
        """The empty string is the other way the column reaches an empty value."""
        self._store_empty(status="")

        self.engagement.save()

        self.assertEqual("Not Started", Engagement.objects.get(pk=self.engagement.pk).status)

    def test_engagement_with_null_engagement_type_can_be_saved(self):
        """`engagement_type` carries the same declaration, so it fails the same way."""
        self._store_empty(engagement_type=None)

        self.engagement.save()

        self.assertEqual(
            "Interactive",
            Engagement.objects.get(pk=self.engagement.pk).engagement_type,
            msg="an empty engagement_type must be normalized to the field default on save",
        )

    def test_a_populated_status_is_left_alone(self):
        """Normalization must only fill in an empty value, never overwrite a real one."""
        self.engagement.status = "In Progress"
        self.engagement.engagement_type = "CI/CD"

        self.engagement.save()

        persisted = Engagement.objects.get(pk=self.engagement.pk)
        self.assertEqual("In Progress", persisted.status)
        self.assertEqual("CI/CD", persisted.engagement_type)

    def test_reimport_into_an_engagement_with_null_status_succeeds(self):
        """The reported path: the closing engagement write-back must not fail the scan."""
        self._store_empty(status=None)

        with (get_unit_tests_scans_path("acunetix") / SCAN_FILE).open(encoding="utf-8") as scan:
            test, _, _, _, _, _, _ = self._reimporter().process_scan(scan)

        self.assertEqual(self.test.pk, test.pk)
        self.assertEqual(
            "Not Started",
            Engagement.objects.get(pk=self.engagement.pk).status,
            msg="the reimport write-back must persist the engagement with a valid status",
        )

    def test_import_into_an_engagement_with_null_status_succeeds(self):
        """The import path shares the same write-back."""
        self._store_empty(status=None)

        with (get_unit_tests_scans_path("acunetix") / SCAN_FILE).open(encoding="utf-8") as scan:
            new_test, _, len_new_findings, _, _, _, _ = self._importer().process_scan(scan)

        self.assertEqual(1, len_new_findings)
        self.assertEqual(self.engagement.pk, new_test.engagement.pk)
        self.assertEqual("Not Started", Engagement.objects.get(pk=self.engagement.pk).status)
