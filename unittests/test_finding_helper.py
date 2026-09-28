import datetime
import logging
from unittest import mock
from unittest.mock import patch

from crum import impersonate
from django.contrib.auth.models import User
from django.db import OperationalError
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.finding.helper import (
    POST_PROCESS_BATCH_MAX_CONFLICT_RETRIES,
    deleted_finding_ids,
    post_process_findings_batch,
    save_vulnerability_ids,
    save_vulnerability_ids_template,
)
from dojo.models import Finding, Finding_Template, Test
from unittests.dojo_test_case import DojoAPITestCase, DojoTestCase, versioned_fixtures

logger = logging.getLogger(__name__)


# frozen_datetime = timezone.make_aware(datetime.datetime(2021, 1, 1, 2, 2, 2), timezone.get_default_timezone())
frozen_datetime = timezone.now()


@versioned_fixtures
class TestUpdateFindingStatusSignal(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.user_1 = User.objects.get(id="1")
        self.user_2 = User.objects.get(id="2")

    def get_status_fields(self, finding):
        logger.debug("%s, %s, %s, %s, %s, %s, %s, %s", finding.active, finding.verified, finding.false_p, finding.out_of_scope, finding.is_mitigated, finding.mitigated, finding.mitigated_by, finding.last_status_update)
        return finding.active, finding.verified, finding.false_p, finding.out_of_scope, finding.is_mitigated, finding.mitigated, finding.mitigated_by, finding.last_status_update

    @mock.patch("dojo.finding.helper.timezone.now")
    def test_new_finding(self, mock_tz):
        mock_tz.return_value = frozen_datetime
        with impersonate(self.user_1):
            test = Test.objects.last()
            finding = Finding(test=test)
            finding.save()

            self.assertEqual(
                self.get_status_fields(finding),
                (True, False, False, False, False, None, None, frozen_datetime),
            )

    @mock.patch("dojo.finding.helper.timezone.now")
    def test_no_status_change(self, mock_tz):
        mock_tz.return_value = frozen_datetime
        with impersonate(self.user_1):
            test = Test.objects.last()
            finding = Finding(test=test)
            finding.save()

            status_fields = self.get_status_fields(finding)

            finding.title += "!!!"
            finding.save()

            self.assertEqual(
                self.get_status_fields(finding),
                status_fields,
            )

    @mock.patch("dojo.finding.helper.timezone.now")
    def test_mark_fresh_as_mitigated(self, mock_dt):
        mock_dt.return_value = frozen_datetime
        with impersonate(self.user_1):
            test = Test.objects.last()
            finding = Finding(test=test, is_mitigated=True, active=False)
            finding.save()
            self.assertEqual(
                self.get_status_fields(finding),
                (False, False, False, False, True, frozen_datetime, self.user_1, frozen_datetime),
            )

    @mock.patch("dojo.finding.helper.timezone.now")
    @mock.patch("dojo.finding.helper.can_edit_mitigated_data", return_value=False)
    def test_mark_old_active_as_mitigated(self, mock_can_edit, mock_tz):
        mock_tz.return_value = frozen_datetime

        with impersonate(self.user_1):
            test = Test.objects.last()
            finding = Finding(test=test, is_mitigated=True, active=False)
            finding.save()
            finding.is_mitigated = True
            finding.active = False
            finding.save()

            self.assertEqual(
                self.get_status_fields(finding),
                (False, False, False, False, True, frozen_datetime, self.user_1, frozen_datetime),
            )

    @mock.patch("dojo.finding.helper.timezone.now")
    @mock.patch("dojo.finding.helper.can_edit_mitigated_data", return_value=True)
    def test_mark_old_active_as_mitigated_custom_edit(self, mock_can_edit, mock_tz):
        mock_tz.return_value = frozen_datetime

        custom_mitigated = datetime.datetime.now(datetime.UTC)

        with impersonate(self.user_1):
            test = Test.objects.last()
            finding = Finding(test=test)
            finding.save()
            finding.is_mitigated = True
            finding.active = False
            finding.mitigated = custom_mitigated
            finding.mitigated_by = self.user_2
            finding.save()

            self.assertEqual(
                self.get_status_fields(finding),
                (False, False, False, False, True, custom_mitigated, self.user_2, frozen_datetime),
            )

    @mock.patch("dojo.finding.helper.timezone.now")
    @mock.patch("dojo.finding.helper.can_edit_mitigated_data", return_value=True)
    def test_update_old_mitigated_with_custom_edit(self, mock_can_edit, mock_tz):
        mock_tz.return_value = frozen_datetime

        custom_mitigated = datetime.datetime.now(datetime.UTC)

        with impersonate(self.user_1):
            test = Test.objects.last()
            finding = Finding(test=test, is_mitigated=True, active=False, mitigated=frozen_datetime, mitigated_by=self.user_1)
            finding.save()
            finding.is_mitigated = True
            finding.active = False
            finding.mitigated = custom_mitigated
            finding.mitigated_by = self.user_2
            finding.save()

            self.assertEqual(
                self.get_status_fields(finding),
                (False, False, False, False, True, custom_mitigated, self.user_2, frozen_datetime),
            )

    @mock.patch("dojo.finding.helper.timezone.now")
    @mock.patch("dojo.finding.helper.can_edit_mitigated_data", return_value=True)
    def test_update_old_mitigated_with_missing_data(self, mock_can_edit, mock_tz):
        mock_tz.return_value = frozen_datetime

        custom_mitigated = datetime.datetime.now(datetime.UTC)

        with impersonate(self.user_1):
            test = Test.objects.last()
            finding = Finding(test=test, is_mitigated=True, active=False, mitigated=custom_mitigated, mitigated_by=self.user_2)
            finding.save()
            finding.is_mitigated = True
            finding.active = False
            # trying to remove mitigated fields will trigger the signal to set them to now/current user
            finding.mitigated = None
            finding.mitigated_by = None
            finding.save()

            self.assertEqual(
                self.get_status_fields(finding),
                (False, False, False, False, True, frozen_datetime, self.user_1, frozen_datetime),
            )

    @mock.patch("dojo.finding.helper.timezone.now")
    @mock.patch("dojo.finding.helper.can_edit_mitigated_data", return_value=True)
    def test_set_old_mitigated_as_active(self, mock_can_edit, mock_tz):
        mock_tz.return_value = frozen_datetime

        with impersonate(self.user_1):
            test = Test.objects.last()
            finding = Finding(test=test, is_mitigated=True, active=False, mitigated=frozen_datetime, mitigated_by=self.user_2)
            logger.debug("save1")
            finding.save()
            finding.active = True
            logger.debug("save2")
            finding.save()

            self.assertEqual(
                self.get_status_fields(finding),
                (True, False, False, False, False, None, None, frozen_datetime),
            )

    @mock.patch("dojo.finding.helper.timezone.now")
    @mock.patch("dojo.finding.helper.can_edit_mitigated_data", return_value=False)
    def test_set_active_as_false_p(self, mock_can_edit, mock_tz):
        mock_tz.return_value = frozen_datetime

        with impersonate(self.user_1):
            test = Test.objects.last()
            finding = Finding(test=test)
            finding.save()
            finding.false_p = True
            finding.save()

            self.assertEqual(
                self.get_status_fields(finding),
                # TODO: marking as false positive resets verified to False, possible bug / undesired behaviour?
                (False, False, True, False, True, frozen_datetime, self.user_1, frozen_datetime),
            )

    @mock.patch("dojo.finding.helper.timezone.now")
    @mock.patch("dojo.finding.helper.can_edit_mitigated_data", return_value=False)
    def test_set_active_as_out_of_scope(self, mock_can_edit, mock_tz):
        mock_tz.return_value = frozen_datetime

        with impersonate(self.user_1):
            test = Test.objects.last()
            finding = Finding(test=test)
            finding.save()
            finding.out_of_scope = True
            finding.save()

            self.assertEqual(
                self.get_status_fields(finding),
                # TODO: marking as false positive resets verified to False, possible bug / undesired behaviour?
                (False, False, False, True, True, frozen_datetime, self.user_1, frozen_datetime),
            )


@versioned_fixtures
class TestDeletedFindingIds(DojoTestCase):

    """
    The one existence lookup every caller holding finding references across a delete window uses.

    Importers buffer child rows and collect import-history candidates for a whole batch
    before writing them, so a finding can be deleted while it is still referenced. Because
    Django's foreign keys are DEFERRABLE INITIALLY DEFERRED, writing such a reference is
    only rejected at COMMIT, so the reference has to be dropped before the write.
    """

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        # duplicate_finding is a self-FK with ON DELETE DO_NOTHING, so a fixture finding
        # another one points at as its original cannot be deleted on its own. These tests
        # are about the existence lookup, not about repairing that reference, so they work
        # on findings nothing points at.
        original_ids = set(
            Finding.objects.exclude(duplicate_finding=None).values_list("duplicate_finding_id", flat=True),
        )
        self.findings = list(Finding.objects.exclude(id__in=original_ids).order_by("id")[:3])
        self.assertEqual(3, len(self.findings), msg="fixture must supply at least 3 deletable findings")

    def test_empty_input_costs_no_query(self):
        with self.assertNumQueries(0):
            self.assertEqual(set(), deleted_finding_ids([]))

    def test_ids_that_are_none_are_ignored_and_cost_no_query(self):
        """An unsaved finding has no row to be missing, so it is not a deleted one."""
        with self.assertNumQueries(0):
            self.assertEqual(set(), deleted_finding_ids([None, None]))

    def test_all_live_findings_returns_empty_set(self):
        live_ids = {finding.id for finding in self.findings}
        with self.assertNumQueries(1):
            self.assertEqual(set(), deleted_finding_ids(live_ids))

    def test_returns_only_the_deleted_ids(self):
        deleted_id = self.findings[0].id
        surviving_ids = {finding.id for finding in self.findings[1:]}
        Finding.objects.filter(id=deleted_id).delete()

        self.assertEqual({deleted_id}, deleted_finding_ids({deleted_id, *surviving_ids}))

    def test_an_id_that_never_existed_counts_as_deleted(self):
        """A caller cannot tell the two apart and wants to skip the reference either way."""
        never_existed = Finding.objects.order_by("-id").first().id + 1000

        self.assertEqual({never_existed}, deleted_finding_ids({never_existed}))

    def test_lookup_is_chunked_so_the_in_clause_stays_bounded(self):
        """
        An import's result set is unbounded, so the ids are asked about a chunk at a time.

        Without this, a large scan puts every finding id it touched into a single IN clause.
        """
        live_ids = {finding.id for finding in self.findings}
        with patch("dojo.finding.helper.FINDING_EXISTENCE_CHUNK", 2), self.assertNumQueries(2):
            self.assertEqual(set(), deleted_finding_ids(live_ids))

    def test_chunking_does_not_change_the_answer(self):
        """Every chunk contributes its survivors, so a deleted id in any chunk is still reported."""
        deleted_id = self.findings[1].id
        all_ids = {finding.id for finding in self.findings}
        Finding.objects.filter(id=deleted_id).delete()

        with patch("dojo.finding.helper.FINDING_EXISTENCE_CHUNK", 1):
            self.assertEqual({deleted_id}, deleted_finding_ids(all_ids))


class TestSaveVulnerabilityIds(DojoTestCase):

    @patch("dojo.finding.helper.persist_for_finding")
    def test_save_vulnerability_ids(self, persist_mock):
        finding = Finding()
        new_vulnerability_ids = ["REF-1", "REF-2", "REF-2"]

        save_vulnerability_ids(finding, new_vulnerability_ids)

        # Delegates the (dual) write to persist_for_finding with deduped/sanitized ids...
        persist_mock.assert_called_once_with(finding, ["REF-1", "REF-2"], delete_existing=True)
        # ...and keeps the cve sync (first id) in the helper.
        self.assertEqual("REF-1", finding.cve)

    @patch("dojo.models.Finding_Template.save")
    def test_save_vulnerability_id_templates(self, save_mock):
        finding_template = Finding_Template()
        new_vulnerability_ids = ["REF-1", "REF-2", "REF-2"]

        save_vulnerability_ids_template(finding_template, new_vulnerability_ids)

        save_mock.assert_called_once()
        self.assertEqual("REF-1\nREF-2", finding_template.vulnerability_ids_text)
        self.assertEqual("REF-1", finding_template.cve)


@versioned_fixtures
class TestFindingVulnerabilityIdsAPI(DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.system_settings(enable_jira=True)
        self.testuser = User.objects.get(username="admin")
        self.testuser.usercontactinfo.block_execution = True
        self.testuser.usercontactinfo.save()
        token = Token.objects.get(user=self.testuser)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        self.client.force_login(self.get_test_admin())

    def test_finding_create_without_cve(self):
        # use existing finding as template for a new finding. this finding has no cve
        finding_details = self.get_finding_api(2)
        del finding_details["id"]
        if "cve" in finding_details:
            del finding_details["cve"]
        new_vulnerability_ids = [
            {"vulnerability_id": "RHSA-12345"},
            {"vulnerability_id": "GHSA-7890"},
        ]
        finding_details["vulnerability_ids"] = new_vulnerability_ids
        response = self.post_new_finding_api(finding_details)
        # assert resopnse data
        self.assertIsNone(response.get("cve"))
        self.assertEqual(new_vulnerability_ids, response.get("vulnerability_ids"))

        # assert GET finding
        finding_id = response.get("id")
        response = self.get_finding_api(finding_id)
        self.assertIsNone(response.get("cve"))
        self.assertEqual(new_vulnerability_ids, response.get("vulnerability_ids"))

    def test_finding_create_with_cve(self):
        # use existing finding as template for a new finding. this finding has no cve
        finding_details = self.get_finding_api(2)
        del finding_details["id"]
        if "cve" in finding_details:
            del finding_details["cve"]
        new_vulnerability_ids = [
            {"vulnerability_id": "CVE-2025-12345"},
            {"vulnerability_id": "RHSA-12345"},
            {"vulnerability_id": "GHSA-7890"},
        ]
        finding_details["vulnerability_ids"] = new_vulnerability_ids
        response = self.post_new_finding_api(finding_details)
        # assert response data
        self.assertEqual(new_vulnerability_ids, response.get("vulnerability_ids"))

        # CVE is not in the response, so get it fromt the database
        self.assertEqual("CVE-2025-12345", Finding.objects.get(id=response.get("id")).cve)

    def test_finding_create_and_update_with_cve(self):
        # use existing finding as template for a new finding. this finding has no cve
        finding_details = self.get_finding_api(2)
        del finding_details["id"]
        if "cve" in finding_details:
            del finding_details["cve"]
        new_vulnerability_ids = [
            {"vulnerability_id": "CVE-2025-12345"},
            {"vulnerability_id": "RHSA-12345"},
            {"vulnerability_id": "GHSA-7890"},
        ]
        finding_details["vulnerability_ids"] = new_vulnerability_ids
        response = self.post_new_finding_api(finding_details)
        finding_id = response.get("id")
        # assert resopnse data
        self.assertEqual(new_vulnerability_ids, response.get("vulnerability_ids"))

        # CVE is not in the response, so get it fromt the database
        self.assertEqual("CVE-2025-12345", Finding.objects.get(id=finding_id).cve)

        # change vulnerability_id and remove cve
        updated_vulnerability_ids = [
            {"vulnerability_id": "RHSA-000000"},
        ]
        response = self.patch_finding_api(finding_id, {"vulnerability_ids": updated_vulnerability_ids})
        # assert resopnse data
        self.assertEqual(updated_vulnerability_ids, response.get("vulnerability_ids"))

        # CVE is not in the response, so get it fromt the database
        # current behaviour is that the cve is taken from the first vulnerability_id...
        self.assertEqual("RHSA-000000", Finding.objects.get(id=finding_id).cve)


class TestPostProcessFindingsBatchDeadlockRetry(DojoTestCase):

    """
    post_process_findings_batch runs the batch dedup / false-positive-history writes that
    update dojo_finding rows. Two of these tasks racing on overlapping rows (concurrent
    imports or connector syncs into the same product) can deadlock -- Postgres aborts one
    with SQLSTATE 40P01. The aborted batch is only rolled back, not wrong, so it must be
    retried rather than surfaced as a failed task. These tests exercise that retry with a
    simulated deadlock so they need no real concurrency.
    """

    def _transient_conflict(self):
        # Mimic how psycopg surfaces a deadlock: Django re-raises the driver error as its
        # own OperationalError and keeps the driver exception -- the one carrying the
        # SQLSTATE -- as __cause__. is_transient_db_conflict inspects both.
        cause = Exception("deadlock detected")
        cause.sqlstate = "40P01"  # deadlock_detected
        exc = OperationalError("deadlock detected")
        exc.__cause__ = cause
        return exc

    def _dedup_enabled_settings(self):
        return mock.Mock(
            enable_deduplication=True,
            false_positive_history=False,
            enable_product_grade=False,
        )

    @patch("dojo.finding.helper.sleep", return_value=None)
    @patch("dojo.finding.helper.dedupe_batch_of_findings")
    @patch("dojo.finding.helper.get_finding_models_for_deduplication")
    @patch("dojo.finding.helper.System_Settings")
    def test_retries_batch_dedupe_on_transient_deadlock(self, mock_ss, mock_get, mock_dedupe, mock_sleep):
        mock_ss.objects.get.return_value = self._dedup_enabled_settings()
        mock_get.return_value = [mock.Mock(id=1)]
        # First two attempts deadlock, the third succeeds.
        mock_dedupe.side_effect = [self._transient_conflict(), self._transient_conflict(), None]

        # Must NOT raise: the batch retries until dedupe succeeds.
        post_process_findings_batch(
            [1],
            dedupe_option=True,
            issue_updater_option=False,
            product_grading_option=False,
            push_to_jira=False,
        )

        self.assertEqual(mock_dedupe.call_count, 3)
        # Findings are reloaded on each attempt so a retry acts on freshly committed state.
        self.assertEqual(mock_get.call_count, 3)

    @patch("dojo.finding.helper.sleep", return_value=None)
    @patch("dojo.finding.helper.dedupe_batch_of_findings")
    @patch("dojo.finding.helper.get_finding_models_for_deduplication")
    @patch("dojo.finding.helper.System_Settings")
    def test_reraises_after_exhausting_retries(self, mock_ss, mock_get, mock_dedupe, mock_sleep):
        mock_ss.objects.get.return_value = self._dedup_enabled_settings()
        mock_get.return_value = [mock.Mock(id=1)]
        # Every attempt deadlocks -> the conflict must surface after retries are exhausted.
        mock_dedupe.side_effect = self._transient_conflict()

        with self.assertRaises(OperationalError):
            post_process_findings_batch(
                [1],
                dedupe_option=True,
                issue_updater_option=False,
                product_grading_option=False,
                push_to_jira=False,
            )

        # Initial try + POST_PROCESS_BATCH_MAX_CONFLICT_RETRIES retries.
        self.assertEqual(mock_dedupe.call_count, POST_PROCESS_BATCH_MAX_CONFLICT_RETRIES + 1)

    @patch("dojo.finding.helper.sleep", return_value=None)
    @patch("dojo.finding.helper.dedupe_batch_of_findings")
    @patch("dojo.finding.helper.get_finding_models_for_deduplication")
    @patch("dojo.finding.helper.System_Settings")
    def test_non_transient_operational_error_not_retried(self, mock_ss, mock_get, mock_dedupe, mock_sleep):
        mock_ss.objects.get.return_value = self._dedup_enabled_settings()
        mock_get.return_value = [mock.Mock(id=1)]
        # A non-deadlock OperationalError (no transient SQLSTATE) is a genuine failure and
        # must propagate immediately, without wasting retries.
        mock_dedupe.side_effect = OperationalError("statement timeout")

        with self.assertRaises(OperationalError):
            post_process_findings_batch(
                [1],
                dedupe_option=True,
                issue_updater_option=False,
                product_grading_option=False,
                push_to_jira=False,
            )

        self.assertEqual(mock_dedupe.call_count, 1)
        mock_sleep.assert_not_called()
