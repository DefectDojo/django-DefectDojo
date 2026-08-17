"""
Unit tests for async_delete functionality.

These tests verify that the async_delete class works correctly with dojo_dispatch_task,
which injects user context and _pgh_context kwargs into task calls.

The original bug was that @app.task decorated instance methods didn't properly handle
the injected kwargs, causing TypeError for unexpected keyword arguments.
"""
import logging
from unittest.mock import patch

from celery.exceptions import Retry
from crum import impersonate
from django.contrib.auth.models import User
from django.db import IntegrityError, OperationalError
from django.test import override_settings
from django.utils import timezone
from parameterized import parameterized
from psycopg.errors import DeadlockDetected, ForeignKeyViolation, QueryCanceled, SerializationFailure, UniqueViolation

from dojo.db_utils import is_foreign_key_conflict, is_transient_db_conflict
from dojo.models import Engagement, Finding, Product, Product_Type, Test, Test_Type, UserContactInfo
from dojo.utils import ASYNC_DELETE_MAX_CONFLICT_RETRIES, async_delete, async_delete_task

from .dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)


class TestAsyncDelete(DojoTestCase):

    """
    Test async_delete functionality with dojo_dispatch_task kwargs injection.

    These tests use block_execution=True and crum.impersonate to run tasks synchronously,
    which allows errors to surface immediately rather than being lost in background workers.
    """

    def setUp(self):
        """Set up test user with block_execution=True and disable unneeded features."""
        super().setUp()

        # Create test user with block_execution=True to run tasks synchronously
        self.testuser = User.objects.create(
            username="test_async_delete_user",
            is_staff=True,
            is_superuser=True,
        )
        UserContactInfo.objects.create(user=self.testuser, block_execution=True)

        # Log in as the test user (for API client)
        self.client.force_login(self.testuser)

        # Disable features that might interfere with deletion
        self.system_settings(enable_product_grade=False)
        self.system_settings(enable_github=False)
        self.system_settings(enable_jira=False)

        # Create base test data
        self.product_type = Product_Type.objects.create(name="Test Product Type for Async Delete")
        self.test_type = Test_Type.objects.get_or_create(name="Manual Test")[0]

    def tearDown(self):
        """Clean up any remaining test data."""
        # Clean up in reverse order of dependencies
        Finding.objects.filter(test__engagement__product__prod_type=self.product_type).delete()
        Test.objects.filter(engagement__product__prod_type=self.product_type).delete()
        Engagement.objects.filter(product__prod_type=self.product_type).delete()
        Product.objects.filter(prod_type=self.product_type).delete()
        self.product_type.delete()

        super().tearDown()

    def _create_product(self, name="Test Product"):
        """Helper to create a product for testing."""
        return Product.objects.create(
            name=name,
            description="Test product for async delete",
            prod_type=self.product_type,
        )

    def _create_engagement(self, product, name="Test Engagement"):
        """Helper to create an engagement for testing."""
        return Engagement.objects.create(
            name=name,
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    def _create_test(self, engagement, name="Test"):
        """Helper to create a test for testing."""
        return Test.objects.create(
            engagement=engagement,
            test_type=self.test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    def _create_finding(self, test, title="Test Finding"):
        """Helper to create a finding for testing."""
        return Finding.objects.create(
            test=test,
            title=title,
            severity="High",
            description="Test finding for async delete",
            mitigation="Test mitigation",
            impact="Test impact",
            reporter=self.testuser,
        )

    @override_settings(ASYNC_OBJECT_DELETE=True)
    def test_async_delete_simple_object(self):
        """
        Test that async_delete works for a simple object (Finding).

        Finding is not in the async_delete mapping, so it falls back to direct delete.
        This tests that the module-level task accepts **kwargs properly.
        """
        product = self._create_product()
        engagement = self._create_engagement(product)
        test = self._create_test(engagement)
        finding = self._create_finding(test)
        finding_pk = finding.pk

        # Use impersonate to set current user context (required for block_execution to work)
        with impersonate(self.testuser):
            # This would raise TypeError before the fix when injected kwargs
            # were not handled properly by task functions
            async_del = async_delete()
            async_del.delete(finding)

        # Verify the finding was deleted
        self.assertFalse(
            Finding.objects.filter(pk=finding_pk).exists(),
            "Finding should be deleted",
        )

    @override_settings(ASYNC_OBJECT_DELETE=True)
    def test_async_delete_test_with_findings(self):
        """
        Test that async_delete cascades deletion for Test objects.

        Test is in the async_delete mapping and should cascade delete its findings.
        """
        product = self._create_product()
        engagement = self._create_engagement(product)
        test = self._create_test(engagement)
        finding1 = self._create_finding(test, "Finding 1")
        finding2 = self._create_finding(test, "Finding 2")

        test_pk = test.pk
        finding1_pk = finding1.pk
        finding2_pk = finding2.pk

        # Use impersonate to set current user context (required for block_execution to work)
        with impersonate(self.testuser):
            # Delete the test (should cascade to findings)
            async_del = async_delete()
            async_del.delete(test)

        # Verify all objects were deleted
        self.assertFalse(
            Test.objects.filter(pk=test_pk).exists(),
            "Test should be deleted",
        )
        self.assertFalse(
            Finding.objects.filter(pk=finding1_pk).exists(),
            "Finding 1 should be deleted via cascade",
        )
        self.assertFalse(
            Finding.objects.filter(pk=finding2_pk).exists(),
            "Finding 2 should be deleted via cascade",
        )

    @override_settings(ASYNC_OBJECT_DELETE=True)
    def test_async_delete_engagement_with_tests(self):
        """
        Test that async_delete cascades deletion for Engagement objects.

        Engagement is in the async_delete mapping and should cascade delete
        its tests and findings.
        """
        product = self._create_product()
        engagement = self._create_engagement(product)
        test1 = self._create_test(engagement, "Test 1")
        test2 = self._create_test(engagement, "Test 2")
        finding1 = self._create_finding(test1, "Finding in Test 1")
        finding2 = self._create_finding(test2, "Finding in Test 2")

        engagement_pk = engagement.pk
        test1_pk = test1.pk
        test2_pk = test2.pk
        finding1_pk = finding1.pk
        finding2_pk = finding2.pk

        # Use impersonate to set current user context (required for block_execution to work)
        with impersonate(self.testuser):
            # Delete the engagement (should cascade to tests and findings)
            async_del = async_delete()
            async_del.delete(engagement)

        # Verify all objects were deleted
        self.assertFalse(
            Engagement.objects.filter(pk=engagement_pk).exists(),
            "Engagement should be deleted",
        )
        self.assertFalse(
            Test.objects.filter(pk__in=[test1_pk, test2_pk]).exists(),
            "Tests should be deleted via cascade",
        )
        self.assertFalse(
            Finding.objects.filter(pk__in=[finding1_pk, finding2_pk]).exists(),
            "Findings should be deleted via cascade",
        )

    @override_settings(ASYNC_OBJECT_DELETE=True)
    def test_async_delete_product_with_hierarchy(self):
        """
        Test that async_delete cascades deletion for Product objects.

        Product is in the async_delete mapping and should cascade delete
        its engagements, tests, and findings.
        """
        product = self._create_product()
        engagement = self._create_engagement(product)
        test = self._create_test(engagement)
        finding = self._create_finding(test)

        product_pk = product.pk
        engagement_pk = engagement.pk
        test_pk = test.pk
        finding_pk = finding.pk

        # Use impersonate to set current user context (required for block_execution to work)
        with impersonate(self.testuser):
            # Delete the product (should cascade to everything)
            async_del = async_delete()
            async_del.delete(product)

        # Verify all objects were deleted
        self.assertFalse(
            Product.objects.filter(pk=product_pk).exists(),
            "Product should be deleted",
        )
        self.assertFalse(
            Engagement.objects.filter(pk=engagement_pk).exists(),
            "Engagement should be deleted via cascade",
        )
        self.assertFalse(
            Test.objects.filter(pk=test_pk).exists(),
            "Test should be deleted via cascade",
        )
        self.assertFalse(
            Finding.objects.filter(pk=finding_pk).exists(),
            "Finding should be deleted via cascade",
        )

    @override_settings(ASYNC_OBJECT_DELETE=True)
    def test_async_delete_accepts_force_sync_kwarg(self):
        """
        Test that async_delete passes through the force_sync kwarg properly.

        The force_sync=True kwarg forces synchronous execution for the top-level task.
        However, nested task dispatches still need user context to run synchronously,
        so we use impersonate here as well.
        """
        product = self._create_product()
        product_pk = product.pk

        # Use impersonate to ensure nested tasks also run synchronously
        with impersonate(self.testuser):
            # Explicitly pass force_sync=True
            async_del = async_delete()
            async_del.delete(product, force_sync=True)

        # Verify the product was deleted
        self.assertFalse(
            Product.objects.filter(pk=product_pk).exists(),
            "Product should be deleted with force_sync=True",
        )

    def test_async_delete_helper_methods(self):
        """
        Test that static helper methods on async_delete class still work.

        These are kept for backwards compatibility.
        """
        product = self._create_product()

        # Test get_object_name
        self.assertEqual(
            async_delete.get_object_name(product),
            "Product",
            "get_object_name should return class name",
        )

        # Test get_object_name with model class
        self.assertEqual(
            async_delete.get_object_name(Product),
            "Product",
            "get_object_name should work with model class",
        )


class TestAsyncDeleteTransientConflictRetry(DojoTestCase):

    # Regression: a Postgres deadlock raised while cascade-deleting aborted
    # async_delete_task outright, so the object was left partly deleted and the
    # failure surfaced to the operator instead of the task simply running again.

    def setUp(self):
        super().setUp()
        self.system_settings(enable_product_grade=False)
        self.product_type = Product_Type.objects.create(name="Product Type for conflict retry")

    def tearDown(self):
        Product.objects.filter(prod_type=self.product_type).delete()
        self.product_type.delete()
        super().tearDown()

    def _create_product(self, name="Product for conflict retry"):
        return Product.objects.create(name=name, description="d", prod_type=self.product_type)

    @staticmethod
    def _wrapped_db_error(driver_error_class):
        """
        Build the exception shape the cloud reports show.

        Django re-raises the driver error as its own OperationalError and keeps the
        psycopg exception -- the one carrying the SQLSTATE -- as ``__cause__``.
        """
        cause = driver_error_class("deadlock detected")
        exc = OperationalError(str(cause))
        exc.__cause__ = cause
        return exc

    @parameterized.expand([
        ("deadlock", DeadlockDetected, True),
        ("serialization_failure", SerializationFailure, True),
        # Control: a statement timeout is not a lost concurrency race. Retrying it
        # would just re-run an already too-slow delete, so it must not be retried.
        ("statement_timeout", QueryCanceled, False),
    ])
    def test_is_transient_db_conflict(self, case_name, driver_error_class, expected):
        exc = self._wrapped_db_error(driver_error_class)
        self.assertEqual(
            is_transient_db_conflict(exc), expected,
            msg=f"{case_name} (sqlstate={exc.__cause__.sqlstate}) classified as "
                f"{is_transient_db_conflict(exc)}, expected {expected}",
        )

    def test_is_transient_db_conflict_without_driver_cause(self):
        """An OperationalError with no driver cause carries no SQLSTATE, so it is not retryable."""
        self.assertFalse(
            is_transient_db_conflict(OperationalError("connection closed")),
            msg="an OperationalError without a SQLSTATE must not be treated as retryable",
        )

    @staticmethod
    def _wrapped_integrity_error(driver_error_class, message="integrity error"):
        """
        Build the IntegrityError shape the cloud reports show.

        Django re-raises the driver error as its own IntegrityError and keeps the
        psycopg exception -- the one carrying the SQLSTATE -- as ``__cause__``.
        """
        cause = driver_error_class(message)
        exc = IntegrityError(str(cause))
        exc.__cause__ = cause
        return exc

    def test_is_foreign_key_conflict(self):
        """
        An FK violation (23503) is the delete-vs-import race; other errors are not.

        The two predicates stay separate: a foreign-key violation is only retryable in
        the delete context, so it must NOT be reported as a generic transient conflict,
        and a deadlock must NOT be reported as a foreign-key conflict.
        """
        fk_exc = self._wrapped_integrity_error(
            ForeignKeyViolation,
            'update or delete on table "dojo_test" violates foreign key constraint '
            '"dojo_test_import_test_id_e8dc3f37_fk_dojo_test_id" on table "dojo_test_import"',
        )
        self.assertTrue(
            is_foreign_key_conflict(fk_exc),
            msg="a foreign-key violation raised while deleting a referenced row must be retryable",
        )
        self.assertFalse(
            is_transient_db_conflict(fk_exc),
            msg="a foreign-key violation is not a deadlock/serialization conflict",
        )
        deadlock = self._wrapped_db_error(DeadlockDetected)
        self.assertFalse(
            is_foreign_key_conflict(deadlock),
            msg="a deadlock is not a foreign-key conflict",
        )

    def test_is_foreign_key_conflict_rejects_other_integrity_errors(self):
        """Control: a unique violation (23505) is a real bug, not the delete-vs-import race."""
        unique_exc = self._wrapped_integrity_error(UniqueViolation, "duplicate key value")
        self.assertFalse(
            is_foreign_key_conflict(unique_exc),
            msg="only foreign-key violations (23503) are the transient delete race",
        )

    def test_foreign_key_conflict_is_retried_rather_than_failing(self):
        """
        The reported failure: an import committed a new Test_Import row referencing a
        Test between the cascade step and the top-level delete, so the delete hit an FK
        violation. On a re-run the cascade step clears the new child and the delete
        completes, so the task must retry rather than surface the error.
        """
        product = self._create_product()
        exc = self._wrapped_integrity_error(
            ForeignKeyViolation,
            'update or delete on table "dojo_test" violates foreign key constraint',
        )

        with patch.object(async_delete_task, "retry", side_effect=Retry()) as mock_retry:
            async_delete_task.push_request(retries=0, is_eager=False)
            try:
                with patch(
                    "dojo.utils_cascade_delete.cascade_delete_related_objects", side_effect=exc,
                ), self.assertRaises(Retry):
                    async_delete_task("dojo.product", product.pk)
            finally:
                async_delete_task.pop_request()

        mock_retry.assert_called_once()
        countdown = mock_retry.call_args.kwargs["countdown"]
        self.assertGreater(
            countdown, 0,
            msg="the retry must be delayed so the racing import's transaction commits "
                f"first, got countdown={countdown}",
        )

    def test_non_fk_integrity_error_is_not_retried(self):
        """Control: an integrity error that is not the delete-vs-import race fails loudly."""
        product = self._create_product()
        exc = self._wrapped_integrity_error(UniqueViolation, "duplicate key value")

        with patch.object(async_delete_task, "retry", side_effect=Retry()) as mock_retry:
            async_delete_task.push_request(retries=0, is_eager=False)
            try:
                with patch(
                    "dojo.utils_cascade_delete.cascade_delete_related_objects", side_effect=exc,
                ), self.assertRaises(IntegrityError):
                    async_delete_task("dojo.product", product.pk)
            finally:
                async_delete_task.pop_request()

        mock_retry.assert_not_called()

    @override_settings(ASYNC_OBJECT_DELETE=True)
    def test_eager_execution_does_not_retry_foreign_key_conflict(self):
        """Eager callers get the FK violation instead of a retry, as with a deadlock."""
        product = self._create_product()
        exc = self._wrapped_integrity_error(
            ForeignKeyViolation, "violates foreign key constraint",
        )

        with patch(
            "dojo.utils_cascade_delete.cascade_delete_related_objects", side_effect=exc,
        ), patch.object(async_delete_task, "retry", side_effect=Retry()) as mock_retry:
            result = async_delete_task.apply(args=("dojo.product", product.pk))

        mock_retry.assert_not_called()
        self.assertTrue(
            isinstance(result.result, IntegrityError),
            msg=f"eager execution must surface the FK violation, got {result.result!r}",
        )

    def test_foreign_key_conflict_surfaces_once_retries_are_exhausted(self):
        """An FK violation that keeps repeating must be reported rather than retried forever."""
        product = self._create_product()
        exc = self._wrapped_integrity_error(
            ForeignKeyViolation, "violates foreign key constraint",
        )

        with patch.object(async_delete_task, "retry", side_effect=Retry()) as mock_retry:
            async_delete_task.push_request(
                retries=ASYNC_DELETE_MAX_CONFLICT_RETRIES, is_eager=False,
            )
            try:
                with patch(
                    "dojo.utils_cascade_delete.cascade_delete_related_objects", side_effect=exc,
                ), self.assertRaises(IntegrityError):
                    async_delete_task("dojo.product", product.pk)
            finally:
                async_delete_task.pop_request()

        mock_retry.assert_not_called()

    @parameterized.expand([
        ("deadlock", DeadlockDetected),
        ("serialization_failure", SerializationFailure),
    ])
    def test_transient_conflict_is_retried_rather_than_failing(self, case_name, driver_error_class):
        """The reported failure: the cascade step deadlocks, so the task must retry it."""
        product = self._create_product()
        exc = self._wrapped_db_error(driver_error_class)

        with patch.object(async_delete_task, "retry", side_effect=Retry()) as mock_retry:
            async_delete_task.push_request(retries=0, is_eager=False)
            try:
                with patch(
                    "dojo.utils_cascade_delete.cascade_delete_related_objects", side_effect=exc,
                ), self.assertRaises(Retry):
                    async_delete_task("dojo.product", product.pk)
            finally:
                async_delete_task.pop_request()

        mock_retry.assert_called_once()
        countdown = mock_retry.call_args.kwargs["countdown"]
        self.assertGreater(
            countdown, 0,
            msg=f"{case_name}: retry must be delayed so the winning transaction commits "
                f"first, got countdown={countdown}",
        )

    def test_delete_completes_when_re_run_after_a_mid_cascade_deadlock(self):
        """
        The claim the retry rests on: re-running after a deadlock finishes the delete.

        A retry is only worth anything if the second run actually completes, so this
        deadlocks partway through the real cascade and then re-invokes the body for
        real -- no mocked cascade on the second pass -- and requires the object to be
        gone. Celery's own retry machinery is not driven here because its only
        in-process re-execution path is the eager one, which this task deliberately
        refuses (see test_eager_execution_does_not_retry); a broker-backed retry is
        integration territory, so what is verified here is that the body is resumable
        and, separately, that retry is called with a sane delay.
        """
        product = self._create_product()
        product_pk = product.pk
        exc = self._wrapped_db_error(DeadlockDetected)

        # First attempt: the cascade step deadlocks, so the object survives.
        with patch.object(async_delete_task, "retry", side_effect=Retry()):
            async_delete_task.push_request(retries=0, is_eager=False)
            try:
                with patch(
                    "dojo.utils_cascade_delete.cascade_delete_related_objects", side_effect=exc,
                ), self.assertRaises(Retry):
                    async_delete_task("dojo.product", product_pk)
            finally:
                async_delete_task.pop_request()

        self.assertTrue(
            Product.objects.filter(pk=product_pk).exists(),
            "the aborted first attempt must leave the object in place, not half-removed",
        )

        # Retry attempt: nothing patched, resuming from whatever the first attempt left.
        async_delete_task.push_request(retries=1, is_eager=False)
        try:
            async_delete_task("dojo.product", product_pk)
        finally:
            async_delete_task.pop_request()

        self.assertFalse(
            Product.objects.filter(pk=product_pk).exists(),
            "re-running after the deadlock must finish the delete",
        )

    @override_settings(ASYNC_OBJECT_DELETE=True)
    def test_eager_execution_does_not_retry(self):
        """
        Eager callers get the error instead of a retry.

        Under ``apply()`` Celery re-runs the body inline and ignores ``countdown``
        (verified against celery 5.6.3), so retrying would re-run the whole delete
        inside the request while the conflicting transaction may still be open.
        """
        product = self._create_product()
        exc = self._wrapped_db_error(DeadlockDetected)

        with patch(
            "dojo.utils_cascade_delete.cascade_delete_related_objects", side_effect=exc,
        ), patch.object(async_delete_task, "retry", side_effect=Retry()) as mock_retry:
            result = async_delete_task.apply(args=("dojo.product", product.pk))

        mock_retry.assert_not_called()
        self.assertTrue(
            isinstance(result.result, OperationalError),
            msg=f"eager execution must surface the deadlock, got {result.result!r}",
        )

    def test_non_conflict_db_error_is_not_retried(self):
        """Control: an error that is not a lost concurrency race still fails loudly."""
        product = self._create_product()
        exc = self._wrapped_db_error(QueryCanceled)

        with patch.object(async_delete_task, "retry", side_effect=Retry()) as mock_retry:
            async_delete_task.push_request(retries=0, is_eager=False)
            try:
                with patch(
                    "dojo.utils_cascade_delete.cascade_delete_related_objects", side_effect=exc,
                ), self.assertRaises(OperationalError):
                    async_delete_task("dojo.product", product.pk)
            finally:
                async_delete_task.pop_request()

        mock_retry.assert_not_called()

    def test_deadlock_surfaces_once_retries_are_exhausted(self):
        """A deadlock that keeps repeating must still be reported rather than retried forever."""
        product = self._create_product()
        exc = self._wrapped_db_error(DeadlockDetected)

        with patch.object(async_delete_task, "retry", side_effect=Retry()) as mock_retry:
            async_delete_task.push_request(
                retries=ASYNC_DELETE_MAX_CONFLICT_RETRIES, is_eager=False,
            )
            try:
                with patch(
                    "dojo.utils_cascade_delete.cascade_delete_related_objects", side_effect=exc,
                ), self.assertRaises(OperationalError):
                    async_delete_task("dojo.product", product.pk)
            finally:
                async_delete_task.pop_request()

        mock_retry.assert_not_called()

    def test_retry_delay_grows_with_each_attempt(self):
        """Successive attempts back off, so a busy table is not hammered by the retries."""
        product = self._create_product()
        exc = self._wrapped_db_error(DeadlockDetected)
        countdowns = []

        for attempt in range(ASYNC_DELETE_MAX_CONFLICT_RETRIES):
            with patch.object(async_delete_task, "retry", side_effect=Retry()) as mock_retry:
                async_delete_task.push_request(retries=attempt, is_eager=False)
                try:
                    with patch(
                        "dojo.utils_cascade_delete.cascade_delete_related_objects", side_effect=exc,
                    ), self.assertRaises(Retry):
                        async_delete_task("dojo.product", product.pk)
                finally:
                    async_delete_task.pop_request()
            countdowns.append(mock_retry.call_args.kwargs["countdown"])

        self.assertEqual(
            countdowns, sorted(countdowns),
            msg=f"countdowns must be non-decreasing across attempts, got {countdowns}",
        )
        self.assertGreater(
            countdowns[-1], countdowns[0],
            msg=f"backoff must grow between the first and last attempt, got {countdowns}",
        )

    def test_post_delete_skip_on_retry_is_logged_as_a_warning(self):
        """
        A conflict after the top-level delete is not recoverable, so it must be loud.

        The retry finds the object already gone and cannot redo product grading; that
        has to reach the log at WARNING rather than being filed as routine INFO.
        """
        product = self._create_product()
        missing_pk = product.pk
        product.delete()

        async_delete_task.push_request(retries=1, is_eager=False)
        try:
            with self.assertLogs("dojo.utils", level="WARNING") as captured:
                async_delete_task("dojo.product", missing_pk)
        finally:
            async_delete_task.pop_request()

        self.assertTrue(
            any("already gone on a retry" in line for line in captured.output),
            msg=f"expected a WARNING about the skipped post-delete work, got {captured.output}",
        )

    def test_missing_object_on_first_call_stays_at_info(self):
        """Control: an object already gone on the first call is routine, not a warning."""
        product = self._create_product()
        missing_pk = product.pk
        product.delete()

        async_delete_task.push_request(retries=0, is_eager=False)
        try:
            with self.assertLogs("dojo.utils", level="INFO") as captured:
                async_delete_task("dojo.product", missing_pk)
        finally:
            async_delete_task.pop_request()

        self.assertFalse(
            any(line.startswith("WARNING") for line in captured.output),
            msg=f"first-call miss must not warn, got {captured.output}",
        )
