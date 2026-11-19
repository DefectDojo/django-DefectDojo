"""
API v3 finding writes that lose the race with a delete of the same finding.

A v3 finding write is not one transaction: ``dojo/finding/services.py`` saves the finding, then
writes its child rows (found_by, vulnerability ids, CWEs, tags) and saves it again. A delete that
commits in between (a single delete, the bulk delete of a test or engagement, the excess-duplicate
delete) leaves those later writes pointing at a finding that is gone. Two errors come out of that:

* a foreign-key violation (SQLSTATE 23503) on a child row, raised when its transaction commits:
  ``set_found_by_locking_finding_first`` takes the finding ``FOR KEY SHARE`` first, so a delete
  that got the finding first wins and the found_by rows are rejected at that COMMIT;
* a forced-update miss on the finding's own save (``Finding.save`` forces an UPDATE of a saved
  finding, so a vanished row raises instead of being re-inserted).

The v2 PATCH answers 404 "This finding was deleted while the update was being processed." for
both. These tests pin the same answer on the v3 PATCH and PUT, and that a write failing while the
finding still exists keeps surfacing as the original error.

The rows are committed for real (``_CommittedFindingsMixin``): a ``TestCase`` never commits, so it
would neither check the deferred foreign key nor leave the forced-update miss outside an atomic
block, which is where the v3 routes run in production. The delete runs inside the found_by write,
at the point a concurrent delete would have committed.
"""
from __future__ import annotations

from contextlib import contextmanager
from unittest import skipUnless
from unittest.mock import patch

from django.conf import settings
from django.db import IntegrityError
from django.test import SimpleTestCase
from psycopg.errors import ForeignKeyViolation
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.db_utils import is_foreign_key_conflict
from dojo.finding import services
from dojo.models import Finding, User
from dojo.utils import get_system_setting
from unittests.test_dedupe_delete_commit_race import _CommittedFindingsMixin

_FOUND_BY = "dojo.finding.services.set_found_by_locking_finding_first"
_REAL_SET_FOUND_BY = services.set_found_by_locking_finding_first
_DELETED_MESSAGE = "This finding was deleted while the update was being processed."


def _deleted_before_found_by_commits(finding, found_by):
    """A delete committed first: the found_by rows are then rejected at their COMMIT."""
    Finding.objects.filter(pk=finding.pk).delete()
    _REAL_SET_FOUND_BY(finding, found_by)


def _deleted_after_found_by_commits(finding, found_by):
    """The found_by rows committed first, then the delete: the finding's own save then misses."""
    _REAL_SET_FOUND_BY(finding, found_by)
    Finding.objects.filter(pk=finding.pk).delete()


def _fk_violation_on_a_present_finding(finding, found_by):
    """
    A foreign-key violation that is not the delete race: the finding is still there.

    Built the way Django surfaces a driver error, the psycopg exception (carrying SQLSTATE 23503)
    kept as ``__cause__``, so the guard classifies it as a foreign-key conflict and has to look the
    finding up before deciding.
    """
    msg = 'insert or update on table "dojo_finding_found_by" violates foreign key constraint'
    cause = ForeignKeyViolation(msg)
    raise IntegrityError(msg) from cause


@skipUnless(settings.V3_FEATURE_LOCATIONS, "API v3 is mounted only when V3_FEATURE_LOCATIONS is enabled (D5)")
class TestApiV3FindingWriteConcurrentDelete(_CommittedFindingsMixin, SimpleTestCase):

    def setUp(self):
        super().setUp()
        admin = User.objects.create(username=f"v3_race_su_{self.suffix}", is_superuser=True, is_staff=True)
        self.addCleanup(User.objects.filter(id=admin.id).delete)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + Token.objects.create(user=admin).key)
        (self.finding,) = self._create_findings(f"v3 write races delete {self.suffix}")

    def _url(self):
        prefix = get_system_setting("url_prefix")
        return f"/{prefix}{settings.API_V3_URL_PREFIX}/findings/{self.finding.pk}"

    @contextmanager
    def _found_by_write(self, side_effect):
        with patch(_FOUND_BY, side_effect=side_effect) as found_by_write:
            yield
        found_by_write.assert_called_once()

    def _patch(self):
        return self.client.patch(self._url(), {"found_by": [self.test.test_type_id]}, format="json", secure=True)

    def _put(self):
        payload = {
            "title": "replaced while deleted",
            "severity": "High",
            "description": "a full replace that races a delete",
            "active": True,
            "verified": False,
            "found_by": [self.test.test_type_id],
        }
        return self.client.put(self._url(), payload, format="json", secure=True)

    def _assert_deleted_404(self, response):
        self.assertEqual(404, response.status_code, response.content[:1000])
        body = response.json()
        self.assertEqual("application/problem+json", response["Content-Type"])
        self.assertTrue(body["type"].endswith("#error-not-found"), body)
        self.assertEqual(_DELETED_MESSAGE, body["detail"], body)
        self.assertFalse(Finding.objects.filter(pk=self.finding.pk).exists())

    def test_patch_foreign_key_violation_on_a_deleted_finding_answers_404(self):
        with self._found_by_write(_deleted_before_found_by_commits):
            response = self._patch()
        self._assert_deleted_404(response)

    def test_put_foreign_key_violation_on_a_deleted_finding_answers_404(self):
        with self._found_by_write(_deleted_before_found_by_commits):
            response = self._put()
        self._assert_deleted_404(response)

    def test_patch_forced_update_miss_on_a_deleted_finding_answers_404(self):
        with self._found_by_write(_deleted_after_found_by_commits):
            response = self._patch()
        self._assert_deleted_404(response)

    def test_put_forced_update_miss_on_a_deleted_finding_answers_404(self):
        with self._found_by_write(_deleted_after_found_by_commits):
            response = self._put()
        self._assert_deleted_404(response)

    def test_foreign_key_violation_on_a_present_finding_is_not_translated(self):
        """Control: with the finding still there the error is a defect, and keeps its 500."""
        for label, write in (("PATCH", self._patch), ("PUT", self._put)):
            with self.subTest(method=label), self._found_by_write(_fk_violation_on_a_present_finding):
                with self.assertRaises(IntegrityError) as caught:
                    write()
                self.assertTrue(is_foreign_key_conflict(caught.exception), caught.exception)
                self.assertTrue(Finding.objects.filter(pk=self.finding.pk).exists())
