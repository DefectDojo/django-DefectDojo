"""
Unit tests for the finding-metadata concurrent-deletion guard.

``POST`` / ``PUT /api/v2/findings/{id}/metadata/`` looks the finding up with ``get_object()``
and then inserts a ``dojo_dojometa`` row for it. The request is not wrapped in a single
transaction (``ATOMIC_REQUESTS = False``), so a concurrent delete of the finding (a bulk
delete, a reimport closing old findings, another pipeline step) can remove the parent
``dojo_finding`` row between the lookup and the insert. The insert then fails with a
foreign-key violation (SQLSTATE 23503) on ``dojo_dojometa.finding_id``, which surfaced as
an opaque 500. On ``PUT`` the same violation was caught by the unique-name ``except
IntegrityError`` and misreported as a 400 "name already exists".

The finding the caller wrote to no longer exists, so both verbs must answer 404, the same
way ``perform_update`` answers a finding PATCH that loses this race. An FK violation while
the finding is still present is a genuine defect and must keep surfacing as the original
error.

Like ``test_finding_patch_concurrent_delete.py``, these call the view helpers directly with
the wrapped-exception shape Django raises, so no database is needed.
"""
from unittest.mock import MagicMock, patch

from django.db import IntegrityError
from django.test import SimpleTestCase
from psycopg.errors import ForeignKeyViolation, UniqueViolation
from rest_framework import status
from rest_framework.exceptions import NotFound

from dojo.finding.api.views import FindingViewSet

META_FK_MESSAGE = (
    'insert or update on table "dojo_dojometa" violates foreign key constraint '
    '"dojo_dojometa_finding_id_5699162b_fk_dojo_finding_id"\n'
    'DETAIL:  Key (finding_id)=(42) is not present in table "dojo_finding".'
)


def _wrapped(exc_class, driver_error_class, message="db error"):
    """Django's shape for a driver error: its own IntegrityError, with the psycopg error as __cause__."""
    cause = driver_error_class(message)
    exc = exc_class(str(cause))
    exc.__cause__ = cause
    return exc


class TestFindingMetadataConcurrentDelete(SimpleTestCase):

    FINDING_PK = 42

    def _request(self, *, name=None):
        request = MagicMock(name="request")
        request.data = {"name": "score", "value": "0.5"}
        request.query_params = {"name": name} if name is not None else {}
        return request

    def _finding(self):
        finding = MagicMock(name="finding")
        finding.pk = self.FINDING_PK
        return finding

    def _call(self, method, request, *, write_error, finding_exists):
        """
        Run a metadata write helper with the DojoMeta write raising ``write_error`` and the
        parent-finding existence check stubbed to ``finding_exists``.
        """
        view = FindingViewSet()
        with (
            patch("dojo.finding.api.views.DojoMeta") as mock_meta,
            patch("dojo.finding.api.views.Finding") as mock_finding,
        ):
            mock_meta.return_value.save.side_effect = write_error
            mock_meta.objects.update_or_create.side_effect = write_error
            mock_finding.objects.filter.return_value.exists.return_value = finding_exists
            return getattr(view, method)(request, self._finding())

    def test_post_on_a_finding_deleted_mid_request_returns_404(self):
        """Regression: the dojo_dojometa FK violation on a vanished finding must be a 404, not a 500."""
        with self.assertRaises(NotFound) as caught:
            self._call(
                "_add_metadata", self._request(),
                write_error=_wrapped(IntegrityError, ForeignKeyViolation, META_FK_MESSAGE),
                finding_exists=False,
            )
        self.assertIn("deleted while the request was being processed", str(caught.exception))

    def test_put_on_a_finding_deleted_mid_request_returns_404(self):
        """Regression: PUT must not misreport the vanished finding as a 400 duplicate name."""
        with self.assertRaises(NotFound) as caught:
            self._call(
                "_edit_metadata", self._request(name="score"),
                write_error=_wrapped(IntegrityError, ForeignKeyViolation, META_FK_MESSAGE),
                finding_exists=False,
            )
        self.assertIn("deleted while the request was being processed", str(caught.exception))

    def test_post_fk_violation_while_finding_still_exists_is_not_translated(self):
        """Control: with the finding still present, the FK violation is a real defect and keeps surfacing."""
        with self.assertRaises(IntegrityError):
            self._call(
                "_add_metadata", self._request(),
                write_error=_wrapped(IntegrityError, ForeignKeyViolation, META_FK_MESSAGE),
                finding_exists=True,
            )

    def test_put_fk_violation_while_finding_still_exists_is_not_translated(self):
        """Control: PUT keeps surfacing a genuine FK defect instead of calling it a duplicate name."""
        with self.assertRaises(IntegrityError):
            self._call(
                "_edit_metadata", self._request(name="score"),
                write_error=_wrapped(IntegrityError, ForeignKeyViolation, META_FK_MESSAGE),
                finding_exists=True,
            )

    def test_put_unique_violation_still_answers_400(self):
        """Control: PUT renaming onto an existing name keeps its existing 400 answer."""
        response = self._call(
            "_edit_metadata", self._request(name="score"),
            write_error=_wrapped(IntegrityError, UniqueViolation, "duplicate key value"),
            finding_exists=False,
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
