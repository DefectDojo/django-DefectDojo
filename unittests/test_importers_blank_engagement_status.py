import logging

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.utils import timezone
from parameterized import parameterized

from dojo.engagement.models import ENGAGEMENT_STATUS_CHOICES
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

from .dojo_test_case import DojoTestCase, get_unit_tests_scans_path, skip_unless_v3

logger = logging.getLogger(__name__)

SCAN_TYPE = "Acunetix Scan"
SCAN_FILE = "one_finding.xml"

# Regression: a reimport into an engagement whose status was empty aborted with
# ValidationError {'status': ['This field cannot be blank.']} and imported nothing.


class TestImportersBlankEngagementStatus(DojoTestCase):

    """
    Regression: an engagement with an empty status could not be saved at all.

    `Engagement.status` is declared `null=True` with a default but without `blank=True`, so
    the database accepts `NULL` while `full_clean()` -- which the base model runs on every
    save -- rejects both `None` and `""` as blank. Rows carrying an empty status therefore
    existed and could never be written again.

    The importer's closing write-back saves the test's engagement on every run, and the only
    engagement field it ever touches is `target_end` (CI/CD engagements only). So a scan into
    such an engagement failed on a field the import never set, and nothing was imported. An
    empty value is not one of ENGAGEMENT_STATUS_CHOICES, so there is nothing to preserve: the
    save applies the declared default instead of failing.
    """

    def setUp(self):
        super().setUp()
        self.user, _ = User.objects.get_or_create(username="admin")
        product_type, _ = Product_Type.objects.get_or_create(name="blank_engagement_status")
        self.environment, _ = Development_Environment.objects.get_or_create(name="Development")
        self.product, _ = Product.objects.get_or_create(
            name="TestImportersBlankEngagementStatus",
            description="Test",
            prod_type=product_type,
        )
        self.engagement, _ = Engagement.objects.get_or_create(
            name="Blank Status Engagement",
            product=self.product,
            engagement_type="CI/CD",
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        with (get_unit_tests_scans_path("acunetix") / SCAN_FILE).open(encoding="utf-8") as scan:
            self.test, _, len_new_findings, _, _, _, _ = self._importer().process_scan(scan)
        self.assertEqual(1, len_new_findings)
        self.default_status = Engagement._meta.get_field("status").default

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

    def _reimporter(self, test):
        return DefaultReImporter(close_old_findings=False, **self._options(test=test))

    def _set_status_bypassing_validation(self, value):
        """
        Write `status` straight to the row, the way the rows this fixes were produced.

        A queryset update issues an UPDATE without instantiating the model, so it skips both
        `pre_save_logic()` and `full_clean()` -- the same as any write made before the base
        model started validating, and the same as loading DefectDojo's sample data, which
        ships an engagement with an empty status.
        """
        Engagement.objects.filter(pk=self.engagement.pk).update(status=value)
        # Re-read the test so its engagement is loaded from the row, not from setUp's copy.
        return Test.objects.get(pk=self.test.pk)

    @parameterized.expand([("",), (None,)])
    def test_reimport_into_engagement_with_blank_status(self, blank_status):
        """The reported failure: the reimport must complete rather than raise on the blank status."""
        test = self._set_status_bypassing_validation(blank_status)

        with (get_unit_tests_scans_path("acunetix") / SCAN_FILE).open(encoding="utf-8") as scan:
            reimported_test, _, len_new_findings, _, _, _, _ = self._reimporter(test).process_scan(scan)

        self.assertEqual(self.test.pk, reimported_test.pk)
        self.assertEqual(
            0, len_new_findings,
            msg=f"the same scan must reimport without new findings, got {len_new_findings}",
        )
        persisted = Engagement.objects.get(pk=self.engagement.pk)
        self.assertEqual(
            self.default_status, persisted.status,
            msg=f"expected status={self.default_status!r}, persisted={persisted.status!r}",
        )

    @parameterized.expand([("",), (None,)])
    def test_saving_an_engagement_with_a_blank_status_applies_the_default(self, blank_status):
        """The lowest level the bug reproduces at: any save of the row, not just an import."""
        self._set_status_bypassing_validation(blank_status)

        engagement = Engagement.objects.get(pk=self.engagement.pk)
        self.assertFalse(
            engagement.status,
            msg=f"the row must start blank for this test to mean anything, got {engagement.status!r}",
        )
        engagement.save()

        persisted = Engagement.objects.get(pk=self.engagement.pk)
        self.assertEqual(
            self.default_status, persisted.status,
            msg=f"expected status={self.default_status!r}, persisted={persisted.status!r}",
        )
        self.assertIn(
            persisted.status, dict(ENGAGEMENT_STATUS_CHOICES),
            msg=f"the healed status must be one of the declared choices, got {persisted.status!r}",
        )

    def test_reimport_leaves_a_populated_status_untouched(self):
        """Control case: the fallback must only fire where the save used to fail."""
        chosen = "Blocked"
        self.assertNotEqual(chosen, self.default_status)
        test = self._set_status_bypassing_validation(chosen)

        with (get_unit_tests_scans_path("acunetix") / SCAN_FILE).open(encoding="utf-8") as scan:
            self._reimporter(test).process_scan(scan)

        persisted = Engagement.objects.get(pk=self.engagement.pk)
        self.assertEqual(
            chosen, persisted.status,
            msg=f"expected status={chosen!r} to survive the reimport, persisted={persisted.status!r}",
        )

    @skip_unless_v3
    def test_a_new_engagement_still_rejects_an_invalid_status(self):
        """
        The fallback replaces an empty status only -- a wrong one must still be rejected.

        Only meaningful with V3_FEATURE_LOCATIONS on, which is what makes the base model run
        `full_clean()` at all; with it off nothing validates the value either way.
        """
        engagement = Engagement(
            name="Bogus Status Engagement",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
            status="Nonsense",
        )
        with self.assertRaises(ValidationError) as caught:
            engagement.save()
        self.assertIn("status", str(caught.exception))

    def test_the_status_column_still_permits_null_for_existing_rows(self):
        """
        Pins why the fix is at save time and not a NOT NULL migration.

        The column stays nullable, so a legacy `NULL` keeps loading instead of turning an
        upgrade into a migration that has to rewrite the table. The heal happens on write.
        """
        try:
            with transaction.atomic():
                Engagement.objects.filter(pk=self.engagement.pk).update(status=None)
        except IntegrityError as exc:  # pragma: no cover -- only if the column is tightened
            self.fail(f"status is expected to stay nullable at the database level: {exc}")
        self.assertIsNone(Engagement.objects.get(pk=self.engagement.pk).status)
