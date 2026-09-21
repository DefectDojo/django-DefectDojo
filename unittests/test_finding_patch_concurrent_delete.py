"""
Unit tests for the finding-update concurrent-deletion guard.

Regression: PATCH 500s with FK violation when finding is deleted mid-request (#2610)

``PATCH /api/v2/findings/{id}/`` is not wrapped in a single transaction
(``ATOMIC_REQUESTS = False``), so a concurrent delete of the target finding -- a reimport
``close_old_findings``, a bulk delete, or another pipeline step -- can remove the parent
``dojo_finding`` row while the update is mid-flight. The child writes then reference a
``finding_id`` that is already gone and raise a foreign-key violation (SQLSTATE 23503):

* the ``dojo_finding_tags`` M2M through-row (OSS), and
* the ``pro_enhanced_finding`` companion (Pro).

The exception handler deliberately keeps a bare FK violation as a 500 (only unique
violations become 409), so the caller saw an opaque Internal Server Error naming a Postgres
constraint. ``FindingViewSet.perform_update`` now catches that specific case -- an FK
violation whose parent finding no longer exists -- and answers 404, because the resource the
client PATCHed genuinely no longer exists. A real FK defect (the finding is still there) must
keep surfacing as a 500.

These tests exercise ``perform_update`` directly with the wrapped-exception shape the cloud
reports show, mirroring ``test_finding_delete_conflict_retry.py`` -- no database needed.
"""
from unittest.mock import MagicMock, patch

from django.db import IntegrityError
from django.test import SimpleTestCase
from psycopg.errors import ForeignKeyViolation, UniqueViolation
from rest_framework.exceptions import NotFound

from dojo.finding.api.views import FindingViewSet

# The two child-write FK violations from the report: the Pro companion and the OSS tag write.
COMPANION_FK_MESSAGE = (
    'insert or update on table "pro_enhanced_finding" violates foreign key constraint '
    '"pro_enhanced_finding_finding_id_8ee99fa3_fk_dojo_finding_id"\n'
    'DETAIL:  Key (finding_id)=(42) is not present in table "dojo_finding".'
)
TAG_FK_MESSAGE = (
    'insert or update on table "dojo_finding_tags" violates foreign key constraint '
    '"dojo_finding_tags_finding_id_d4968e76_fk_dojo_finding_id"\n'
    'DETAIL:  Key (finding_id)=(42) is not present in table "dojo_finding".'
)


def _wrapped(exc_class, driver_error_class, message="db error"):
    """
    Build the exception shape Django surfaces for a driver error.

    Django re-raises the driver error as its own IntegrityError and keeps the psycopg
    exception -- the one carrying the SQLSTATE -- as ``__cause__``. ``is_foreign_key_conflict``
    reads the SQLSTATE off that cause, so the wrapping has to be reproduced here.
    """
    cause = driver_error_class(message)
    exc = exc_class(str(cause))
    exc.__cause__ = cause
    return exc


class TestPerformUpdateConcurrentDelete(SimpleTestCase):

    FINDING_PK = 42

    def _serializer(self):
        serializer = MagicMock(name="serializer")
        serializer.instance.pk = self.FINDING_PK
        serializer.validated_data = {}
        return serializer

    def _perform_update(self, serializer, *, finding_exists):
        """
        Call ``FindingViewSet.perform_update`` with jira disabled and the parent-finding
        existence check stubbed to ``finding_exists``.
        """
        view = FindingViewSet()
        with (
            patch("dojo.finding.api.views.get_system_setting", return_value=False),
            patch("dojo.finding.api.views.jira_services.get_project", return_value=None),
            patch("dojo.finding.api.views.Finding") as mock_finding,
        ):
            mock_finding.objects.filter.return_value.exists.return_value = finding_exists
            view.perform_update(serializer)

    def test_finding_deleted_mid_update_returns_404(self):
        """Both child-write FK violations, with the parent gone, must become a 404 (NotFound)."""
        for label, message in (("companion", COMPANION_FK_MESSAGE), ("tags", TAG_FK_MESSAGE)):
            with self.subTest(write=label):
                serializer = self._serializer()
                serializer.save.side_effect = _wrapped(IntegrityError, ForeignKeyViolation, message)
                with self.assertRaises(NotFound) as caught:
                    self._perform_update(serializer, finding_exists=False)
                self.assertIn(
                    "deleted while the update was being processed",
                    str(caught.exception),
                    msg=f"the {label} FK violation on a vanished finding must report the deletion, "
                        f"got: {caught.exception}",
                )

    def test_fk_violation_while_finding_still_exists_is_not_translated(self):
        """
        Control: an FK violation while the finding is still present is a genuine defect and
        must keep surfacing as the original IntegrityError (a 500), not a 404.
        """
        serializer = self._serializer()
        serializer.save.side_effect = _wrapped(IntegrityError, ForeignKeyViolation, COMPANION_FK_MESSAGE)
        with self.assertRaises(IntegrityError):
            self._perform_update(serializer, finding_exists=True)

    def test_non_fk_integrity_error_is_not_translated(self):
        """Control: a unique violation (23505) is not the delete race and must not become a 404."""
        serializer = self._serializer()
        serializer.save.side_effect = _wrapped(IntegrityError, UniqueViolation, "duplicate key value")
        with self.assertRaises(IntegrityError):
            self._perform_update(serializer, finding_exists=False)

    def test_successful_update_saves_and_does_not_raise(self):
        """Control: an ordinary update saves once and raises nothing."""
        serializer = self._serializer()
        serializer.save.return_value = None
        self._perform_update(serializer, finding_exists=True)
        serializer.save.assert_called_once_with(push_to_jira=None)
