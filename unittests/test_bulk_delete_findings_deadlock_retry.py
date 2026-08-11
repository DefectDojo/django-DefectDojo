"""
Unit tests for the transient-conflict retry in the chunked bulk finding delete.

The synchronous bulk finding delete (``/findings/bulk_delete/``) runs each chunk in its
own ``transaction.atomic()``. When that delete overlaps a concurrent import or dedup, the
two transactions can update the same ``dojo_finding`` rows in opposite order and Postgres
aborts one with ``deadlock detected`` (SQLSTATE 40P01). Deterministic lock ordering rules
out most such races, but not this one, so a lost race must be retried rather than surfaced
to the caller as a 500 -- mirroring the backstop the async cascade-delete task already has.

A deadlock rolls the whole chunk transaction back, so re-running the chunk is safe and
earlier committed chunks are untouched. Only transient conflicts (deadlock / serialization
failure) are retried; any other database error, and a conflict that survives every attempt,
must still propagate.
"""

import logging

from django.db import OperationalError
from django.utils import timezone

from dojo import utils_cascade_delete
from dojo.finding import helper as finding_helper
from dojo.finding.helper import BULK_DELETE_MAX_CONFLICT_RETRIES, bulk_delete_findings
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

logger = logging.getLogger(__name__)


def _transient_conflict():
    """
    Build an OperationalError that ``is_transient_db_conflict`` treats as retryable.

    In production Django re-raises the driver error as its own OperationalError and keeps
    the psycopg exception -- the one carrying the 40P01 SQLSTATE -- as ``__cause__``, so
    the SQLSTATE is fabricated on the cause here rather than on the message text.
    """
    cause = Exception("deadlock detected")
    cause.sqlstate = "40P01"
    exc = OperationalError("deadlock detected")
    exc.__cause__ = cause
    return exc


class TestBulkDeleteFindingsDeadlockRetry(DojoTestCase):

    """A chunk that loses a concurrency race is retried; other failures are not."""

    def setUp(self):
        super().setUp()
        self.testuser = User.objects.create(
            username="bulk_delete_deadlock_user",
            is_staff=True,
            is_superuser=True,
        )
        UserContactInfo.objects.create(user=self.testuser, block_execution=True)
        self.system_settings(enable_deduplication=False)
        self.system_settings(enable_product_grade=False)

        self.product_type = Product_Type.objects.create(name="Bulk Delete Deadlock PT")
        self.product = Product.objects.create(
            name="Bulk Delete Deadlock Product",
            description="Test",
            prod_type=self.product_type,
        )
        self.test_type = Test_Type.objects.get_or_create(name="Manual Test")[0]
        self.engagement = Engagement.objects.create(
            name="Bulk Delete Deadlock Engagement",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.test = Test.objects.create(
            engagement=self.engagement,
            test_type=self.test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        # The retry backs off with sleep(); make it a no-op so the tests stay fast and
        # deterministic rather than actually waiting between attempts.
        self._real_sleep = finding_helper.sleep
        finding_helper.sleep = lambda _seconds: None

    def tearDown(self):
        finding_helper.sleep = self._real_sleep
        super().tearDown()

    def _create_finding(self, title):
        return Finding.objects.create(
            test=self.test,
            title=title,
            severity="High",
            description="Test",
            mitigation="Test",
            impact="Test",
            reporter=self.testuser,
        )

    def _delete_with_execute_delete_sql(self, findings, fake_execute):
        """
        Run the bulk delete with ``execute_delete_sql`` replaced by ``fake_execute``.

        The delete imports ``execute_delete_sql`` from ``utils_cascade_delete`` at call
        time, so the patch has to land on the defining module -- the same seam the M2M
        tests use.
        """
        real_execute_delete_sql = utils_cascade_delete.execute_delete_sql
        utils_cascade_delete.execute_delete_sql = fake_execute
        try:
            bulk_delete_findings(
                Finding.objects.filter(id__in=[finding.id for finding in findings]),
                # One chunk for the whole set, so each attempt is a single delete call.
                chunk_size=100,
            )
        finally:
            utils_cascade_delete.execute_delete_sql = real_execute_delete_sql

    def test_transient_conflict_on_chunk_is_retried_and_succeeds(self):
        """A deadlock on the first attempt is retried, and the chunk then deletes."""
        first = self._create_finding("Deadlock F1")
        second = self._create_finding("Deadlock F2")

        real_execute_delete_sql = utils_cascade_delete.execute_delete_sql
        state = {"calls": 0}

        def execute_delete_sql_deadlock_once(queryset, *args, **kwargs):
            state["calls"] += 1
            if state["calls"] == 1:
                raise _transient_conflict()
            return real_execute_delete_sql(queryset, *args, **kwargs)

        self._delete_with_execute_delete_sql([first, second], execute_delete_sql_deadlock_once)

        self.assertEqual(state["calls"], 2, "The chunk should have been attempted twice: one conflict, one success.")
        self.assertFalse(
            Finding.objects.filter(id__in=[first.id, second.id]).exists(),
            "Both findings should have been deleted after the retry.",
        )

    def test_non_transient_operational_error_is_not_retried(self):
        """A non-conflict OperationalError (e.g. a statement timeout) must propagate at once."""
        first = self._create_finding("Deadlock F3")
        second = self._create_finding("Deadlock F4")

        state = {"calls": 0}

        def execute_delete_sql_timeout(queryset, *args, **kwargs):
            state["calls"] += 1
            msg = "canceling statement due to statement timeout"
            raise OperationalError(msg)

        with self.assertRaises(OperationalError):
            self._delete_with_execute_delete_sql([first, second], execute_delete_sql_timeout)

        self.assertEqual(state["calls"], 1, "A non-transient error must not be retried.")
        self.assertTrue(
            Finding.objects.filter(id__in=[first.id, second.id]).exists(),
            "The findings must survive a failed delete that was not retried.",
        )

    def test_persistent_transient_conflict_gives_up_after_max_retries(self):
        """A conflict that never clears is retried a bounded number of times, then raised."""
        first = self._create_finding("Deadlock F5")
        second = self._create_finding("Deadlock F6")

        state = {"calls": 0}

        def execute_delete_sql_always_deadlock(queryset, *args, **kwargs):
            state["calls"] += 1
            raise _transient_conflict()

        with self.assertRaises(OperationalError):
            self._delete_with_execute_delete_sql([first, second], execute_delete_sql_always_deadlock)

        self.assertEqual(
            state["calls"],
            BULK_DELETE_MAX_CONFLICT_RETRIES + 1,
            "The chunk should be tried once plus the configured number of retries.",
        )
        self.assertTrue(
            Finding.objects.filter(id__in=[first.id, second.id]).exists(),
            "Nothing should be deleted when every attempt loses the race.",
        )
