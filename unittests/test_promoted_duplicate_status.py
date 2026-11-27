"""
The status a duplicate keeps when its original is deleted and it becomes the cluster's original.

Regression: deleting an original copied its active, verified and is_mitigated onto the promoted
duplicate (but not mitigated or mitigated_by), so an open duplicate of a mitigated original came
back is_mitigated=True with no mitigation date, and a mitigated duplicate of an open original came
back active. The promoted finding keeps its own status: it is active unless it is closed for a
reason of its own (mitigated, false positive, out of scope or risk accepted).
"""

import datetime

from crum import impersonate
from django.test.utils import override_settings
from django.utils import timezone

from dojo.finding.helper import _bulk_delete_findings_internal, prepare_duplicates_for_delete
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

MITIGATED_AT = datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.UTC)

# (name, original's status, duplicate's own status, the promoted finding's expected status)
OPEN = {"active": True, "verified": True, "is_mitigated": False, "mitigated": None}
MITIGATED = {"active": False, "verified": False, "is_mitigated": True, "mitigated": MITIGATED_AT}
CASES = [
    # The reported case: an open duplicate of a mitigated original stays open and unmitigated.
    ("open_duplicate_of_mitigated_original", MITIGATED, {"verified": True},
     {"active": True, "verified": True, "is_mitigated": False, "mitigated": None}),
    # The mirror case: a mitigated duplicate of an open original stays mitigated, with its date.
    ("mitigated_duplicate_of_open_original", OPEN, {"is_mitigated": True, "mitigated": MITIGATED_AT, "verified": False},
     {"active": False, "verified": False, "is_mitigated": True, "mitigated": MITIGATED_AT}),
    # Closed for another reason of its own: false positive, out of scope, risk accepted.
    ("false_positive_duplicate", OPEN, {"false_p": True}, {"active": False, "is_mitigated": False}),
    ("out_of_scope_duplicate", OPEN, {"out_of_scope": True}, {"active": False, "is_mitigated": False}),
    ("risk_accepted_duplicate", OPEN, {"risk_accepted": True}, {"active": False, "is_mitigated": False}),
    # Control: an open duplicate of an open original is open after the promotion, as before.
    ("open_duplicate_of_open_original", OPEN, {"verified": False},
     {"active": True, "verified": False, "is_mitigated": False, "mitigated": None}),
]


@override_settings(DUPLICATE_CLUSTER_CASCADE_DELETE=False)
class TestPromotedDuplicateKeepsItsOwnStatus(DojoTestCase):

    def setUp(self):
        super().setUp()
        self.user = User.objects.create(username="promoted_status_user", is_staff=True, is_superuser=True)
        UserContactInfo.objects.create(user=self.user, block_execution=True)
        self.system_settings(enable_deduplication=False)
        self.system_settings(enable_product_grade=False)
        product = Product.objects.create(
            name="Promoted Status Product", description="Test",
            prod_type=Product_Type.objects.create(name="Promoted Status PT"),
        )
        test_type = Test_Type.objects.get_or_create(name="Manual Test")[0]
        self.tests = []
        for name in ("Original engagement", "Duplicate engagement"):
            engagement = Engagement.objects.create(
                name=name, product=product, target_start=timezone.now(), target_end=timezone.now(),
            )
            self.tests.append(Test.objects.create(
                engagement=engagement, test_type=test_type, target_start=timezone.now(), target_end=timezone.now(),
            ))

    def _finding(self, test, title, **status):
        finding = Finding(
            test=test, title=title, severity="High", description="Test", reporter=self.user, **status,
        )
        # The raw save skips Finding.save()'s status handling, so each field is exactly as given.
        super(Finding, finding).save(skip_validation=True)
        return finding

    def _cluster(self, original_status, duplicate_status):
        original = self._finding(self.tests[0], "Original", **original_status)
        # A duplicate is inactive because it is a duplicate, whatever its own status.
        duplicate = self._finding(
            self.tests[1], "Duplicate", duplicate=True, duplicate_finding=original, active=False, **duplicate_status,
        )
        return original, duplicate

    def _assert_promoted(self, duplicate, expected):
        promoted = Finding.objects.get(id=duplicate.id)
        persisted = {field: getattr(promoted, field) for field in expected}
        self.assertFalse(promoted.duplicate)
        self.assertIsNone(promoted.duplicate_finding_id)
        self.assertEqual(persisted, expected, msg=f"expected {expected}, persisted {persisted}")
        self.assertFalse(
            promoted.is_mitigated and promoted.mitigated is None,
            msg=f"promoted finding is_mitigated={promoted.is_mitigated} with mitigated={promoted.mitigated}",
        )

    def test_finding_delete(self):
        """Deleting the original finding (finding_delete -> reconfigure_duplicate_cluster)."""
        for name, original_status, duplicate_status, expected in CASES:
            with self.subTest(name):
                original, duplicate = self._cluster(original_status, duplicate_status)
                with impersonate(self.user):
                    original.delete()
                self._assert_promoted(duplicate, expected)

    def test_test_delete(self):
        """Deleting the original's test (prepare_duplicates_for_delete -> reconfigure_duplicate_cluster)."""
        for name, original_status, duplicate_status, expected in CASES:
            with self.subTest(name):
                original, duplicate = self._cluster(original_status, duplicate_status)
                with impersonate(self.user):
                    prepare_duplicates_for_delete(self.tests[0])
                self._assert_promoted(duplicate, expected)
                Finding.objects.filter(id=original.id).delete()

    def test_bulk_delete(self):
        """Bulk deleting the original (resolve_inbound_duplicate_references promotes the survivor)."""
        for name, original_status, duplicate_status, expected in CASES:
            with self.subTest(name):
                original, duplicate = self._cluster(original_status, duplicate_status)
                with impersonate(self.user):
                    _bulk_delete_findings_internal(Finding.objects.filter(id=original.id))
                self.assertFalse(Finding.objects.filter(id=original.id).exists())
                self._assert_promoted(duplicate, expected)
