"""
Unit tests for the synchronous single-finding delete conflict retry.

A single-finding delete (API ``DELETE /api/v2/findings/{id}/`` and the UI delete view)
runs Django's collector, which clears the finding's ``Test_Import_Finding_Action`` children
before deleting the finding row. Those FK constraints are ``DEFERRABLE INITIALLY DEFERRED``,
so a concurrent import that commits a new child row referencing this finding between the
child clear and the transaction COMMIT trips a foreign-key violation (SQLSTATE 23503) at
commit time -- surfaced to the caller as an Internal Server Error.

``delete_finding_with_conflict_retry`` re-runs the delete for that transient race, mirroring
the async cascade delete's ``_is_retryable_delete_conflict`` handling. These tests mock
``Finding.delete`` so the retry logic is exercised without touching the database.
"""
from unittest.mock import MagicMock, patch

from django.db import IntegrityError, OperationalError
from django.test import SimpleTestCase
from psycopg.errors import DeadlockDetected, ForeignKeyViolation, SerializationFailure, UniqueViolation

from dojo.finding.helper import SINGLE_DELETE_MAX_CONFLICT_RETRIES, delete_finding_with_conflict_retry


def _wrapped(exc_class, driver_error_class, message="db error"):
    """
    Build the exception shape the cloud reports show.

    Django re-raises the driver error as its own IntegrityError/OperationalError and keeps
    the psycopg exception -- the one carrying the SQLSTATE -- as ``__cause__``.
    """
    cause = driver_error_class(message)
    exc = exc_class(str(cause))
    exc.__cause__ = cause
    return exc


class TestDeleteFindingWithConflictRetry(SimpleTestCase):

    def _finding(self):
        finding = MagicMock(name="finding")
        finding.pk = 3109377
        return finding

    def test_success_on_first_attempt_deletes_once(self):
        finding = self._finding()
        with patch("dojo.finding.helper.sleep") as mock_sleep:
            delete_finding_with_conflict_retry(finding, push_to_jira=False)
        finding.delete.assert_called_once_with(push_to_jira=False)
        mock_sleep.assert_not_called()

    def test_foreign_key_conflict_is_retried_then_succeeds(self):
        """
        The reported failure: a concurrent import committed a Test_Import_Finding_Action
        row referencing the finding between the child clear and COMMIT, so the delete hit a
        deferred FK violation. On a re-run the collector clears the new child and the delete
        completes, so the caller must not see a 500.
        """
        finding = self._finding()
        fk_exc = _wrapped(
            IntegrityError,
            ForeignKeyViolation,
            'update or delete on table "dojo_finding" violates foreign key constraint '
            '"dojo_test_import_fin_finding_id_28fe8e2d_fk_dojo_find" on table '
            '"dojo_test_import_finding_action"',
        )
        finding.delete.side_effect = [fk_exc, None]
        with patch("dojo.finding.helper.sleep") as mock_sleep:
            delete_finding_with_conflict_retry(finding, push_to_jira=False)
        self.assertEqual(finding.delete.call_count, 2)
        mock_sleep.assert_called_once()

    def test_transient_conflict_is_retried_then_succeeds(self):
        for driver_error_class in (DeadlockDetected, SerializationFailure):
            with self.subTest(driver=driver_error_class.__name__):
                finding = self._finding()
                exc = _wrapped(OperationalError, driver_error_class)
                finding.delete.side_effect = [exc, None]
                with patch("dojo.finding.helper.sleep"):
                    delete_finding_with_conflict_retry(finding)
                self.assertEqual(finding.delete.call_count, 2)

    def test_non_retryable_integrity_error_is_not_retried(self):
        """Control: a unique violation (23505) is a real bug, not the delete-vs-import race."""
        finding = self._finding()
        unique_exc = _wrapped(IntegrityError, UniqueViolation, "duplicate key value")
        finding.delete.side_effect = unique_exc
        with patch("dojo.finding.helper.sleep") as mock_sleep, self.assertRaises(IntegrityError):
            delete_finding_with_conflict_retry(finding)
        finding.delete.assert_called_once()
        mock_sleep.assert_not_called()

    def test_conflict_surfaces_once_retries_are_exhausted(self):
        """A conflict that keeps repeating must be reported rather than retried forever."""
        finding = self._finding()
        fk_exc = _wrapped(IntegrityError, ForeignKeyViolation, "violates foreign key constraint")
        finding.delete.side_effect = fk_exc
        with patch("dojo.finding.helper.sleep"), self.assertRaises(IntegrityError):
            delete_finding_with_conflict_retry(finding)
        self.assertEqual(finding.delete.call_count, SINGLE_DELETE_MAX_CONFLICT_RETRIES + 1)

    def test_retry_backoff_grows_with_each_attempt(self):
        finding = self._finding()
        fk_exc = _wrapped(IntegrityError, ForeignKeyViolation, "violates foreign key constraint")
        finding.delete.side_effect = fk_exc
        with patch("dojo.finding.helper.sleep") as mock_sleep, self.assertRaises(IntegrityError):
            delete_finding_with_conflict_retry(finding)
        delays = [call.args[0] for call in mock_sleep.call_args_list]
        self.assertEqual(len(delays), SINGLE_DELETE_MAX_CONFLICT_RETRIES)
        self.assertEqual(delays, sorted(delays))
        self.assertLess(delays[0], delays[-1])
