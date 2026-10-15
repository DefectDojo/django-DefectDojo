import datetime
from unittest.mock import Mock, patch

from django.db import connection
from django.db.models import query as django_query
from django.db.utils import OperationalError
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from dojo.jira.models import JIRA_Issue
from dojo.models import Finding, Test_Type
from dojo.notifications.helper import sla_compute_and_notify
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


# Regression: the daily SLA task ended the whole run at the first finding that raised, so no
# SLA notification went out for any finding, and it loaded every open finding into memory.
@versioned_fixtures
@override_settings(SLA_NOTIFY_PRE_BREACH=3, SLA_NOTIFY_POST_BREACH=7)
class TestSlaComputeAndNotify(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.system_settings(
            enable_finding_sla=True,
            enable_notify_sla_active=True,
            enable_notify_sla_active_verified=False,
            enable_notify_sla_jira_only=False,
            enable_notify_sla_exponential_backoff=False,
        )
        # Only the findings this test creates are in scope.
        Finding.objects.update(active=False)
        product = self.create_product("SLA notify product")
        engagement = self.create_engagement("SLA notify engagement", product)
        Test_Type.objects.get_or_create(name="SLA notify scan")
        self.test = self.create_test(engagement=engagement, scan_type="SLA notify scan", title="SLA notify test")

    def _finding(self, title, days_remaining):
        finding = Finding(
            test=self.test,
            title=title,
            severity="High",
            active=True,
            verified=False,
            is_mitigated=False,
            duplicate=False,
            reporter=self.get_test_admin(),
        )
        finding.save()
        # save() derives the expiration date from the SLA configuration; pin it so the test
        # controls exactly where each finding sits relative to the notify window.
        expiration = timezone.now().date() + datetime.timedelta(days=days_remaining)
        Finding.objects.filter(pk=finding.pk).update(sla_expiration_date=expiration)
        return Finding.objects.get(pk=finding.pk)

    @staticmethod
    def _notified_finding_ids(mock_create_notification):
        return sorted(
            call.kwargs["finding"].id
            for call in mock_create_notification.call_args_list
            if call.kwargs.get("event") == "sla_breach"
        )

    @patch("dojo.notifications.helper.create_notification")
    def test_one_failing_finding_does_not_stop_notifications_for_the_rest(self, mock_create_notification):
        healthy_before = self._finding("healthy, breached", -2)
        broken = self._finding("raises while computing its SLA", -1)
        healthy_after = self._finding("healthy, pre-breach", 2)

        original_get_sla_period = Finding.get_sla_period

        def get_sla_period(finding):
            if finding.id == broken.id:
                msg = "simulated failure for one finding"
                raise RuntimeError(msg)
            return original_get_sla_period(finding)

        with patch.object(Finding, "get_sla_period", autospec=True, side_effect=get_sla_period):
            sla_compute_and_notify()

        notified = self._notified_finding_ids(mock_create_notification)
        expected = sorted([healthy_before.id, healthy_after.id])
        self.assertEqual(
            notified, expected,
            msg=f"expected sla_breach notifications for {expected}, got {notified}",
        )

    @patch("dojo.notifications.helper.create_notification")
    def test_one_failing_notification_does_not_stop_the_rest(self, mock_create_notification):
        first = self._finding("first", -1)
        second = self._finding("second", -1)

        def create_notification(**kwargs):
            if kwargs.get("event") == "sla_breach" and kwargs["finding"].id == first.id:
                msg = "simulated failure while notifying"
                raise RuntimeError(msg)

        mock_create_notification.side_effect = create_notification
        sla_compute_and_notify()

        attempted = self._notified_finding_ids(mock_create_notification)
        self.assertEqual(attempted, sorted([first.id, second.id]), msg=f"notification attempts: {attempted}")
        combined = [c for c in mock_create_notification.call_args_list if c.kwargs.get("event") == "sla_breach_combined"]
        self.assertEqual(len(combined), 1, msg=f"combined notifications: {combined}")

    @patch("dojo.notifications.helper.create_notification")
    def test_findings_outside_the_notify_window_are_not_evaluated(self, mock_create_notification):
        in_window = [
            self._finding("breached within the post-breach window", -7),
            self._finding("breaching today", 0),
            self._finding("pre-breach", 3),
        ]
        out_of_window = [
            self._finding("breached too long ago", -8),
            self._finding("not due for a while", 4),
        ]

        with patch.object(Finding, "get_sla_period", autospec=True, side_effect=Finding.get_sla_period) as spy:
            sla_compute_and_notify()

        evaluated = sorted(call.args[0].id for call in spy.call_args_list)
        expected = sorted(f.id for f in in_window)
        self.assertEqual(
            evaluated, expected,
            msg=f"get_sla_period ran for {evaluated}; out-of-window ids {[f.id for f in out_of_window]} should be filtered in the database",
        )
        self.assertEqual(self._notified_finding_ids(mock_create_notification), expected)

    @patch("dojo.notifications.helper.create_notification")
    def test_finding_without_an_expiration_date_is_still_treated_as_breaching_today(self, mock_create_notification):
        finding = self._finding("no expiration date", 0)
        Finding.objects.filter(pk=finding.pk).update(sla_expiration_date=None)

        sla_compute_and_notify()

        breaching = [
            c.kwargs["finding"].id for c in mock_create_notification.call_args_list
            if c.kwargs.get("event") == "sla_breach" and "breaching today" in c.kwargs["title"]
        ]
        self.assertEqual(breaching, [finding.id], msg=f"breaching-today notifications: {breaching}")

    @patch("dojo.notifications.helper.create_notification")
    def test_query_count_does_not_grow_with_each_notified_finding(self, mock_create_notification):
        self._finding("one", -1)
        with CaptureQueriesContext(connection) as one:
            sla_compute_and_notify()

        for i in range(3):
            self._finding(f"more {i}", -1)
        with CaptureQueriesContext(connection) as four:
            sla_compute_and_notify()

        # Each finding runs in its own savepoint; those statements are bookkeeping, not lookups.
        def data_queries(ctx):
            return [q["sql"] for q in ctx.captured_queries if "SAVEPOINT" not in q["sql"]]

        self.assertEqual(
            len(data_queries(four)), len(data_queries(one)),
            msg=f"queries with 1 finding: {len(data_queries(one))}, with 4 findings: {len(data_queries(four))}\n"
            + "\n".join(q[:200] for q in data_queries(four)),
        )

    def _link_jira_issue(self, finding):
        return JIRA_Issue.objects.create(finding=finding, jira_id=f"{finding.id}", jira_key=f"SLA-{finding.id}")

    @patch("dojo.jira.services.add_simple_comment")
    @patch("dojo.jira.services.get_project")
    @patch("dojo.jira.services.get_instance")
    @patch("dojo.notifications.helper.create_notification")
    def test_jira_comment_goes_to_each_findings_own_jira_instance(self, mock_create_notification, mock_get_instance, mock_get_project, mock_add_comment):
        first = self._finding("first", -1)
        second = self._finding("second", -1)
        issues = {f.id: self._link_jira_issue(f) for f in (first, second)}
        instances = {f.id: Mock(name=f"jira instance for {f.id}", global_jira_sla_notification=True) for f in (first, second)}
        mock_get_instance.side_effect = lambda finding: instances[finding.id]
        mock_get_project.return_value = Mock(product_jira_sla_notification=False)

        sla_compute_and_notify()

        commented = sorted((call.args[1].id, call.args[0]._mock_name) for call in mock_add_comment.call_args_list)
        expected = sorted((issues[f.id].id, instances[f.id]._mock_name) for f in (first, second))
        self.assertEqual(commented, expected, msg=f"(jira issue, jira instance) pairs commented: {commented}")

    @patch("dojo.jira.services.add_simple_comment")
    @patch("dojo.jira.services.get_project", side_effect=RuntimeError("product has no JIRA project"))
    @patch("dojo.jira.services.get_instance")
    @patch("dojo.notifications.helper.create_notification")
    def test_missing_jira_project_does_not_fail_the_finding(self, mock_create_notification, mock_get_instance, mock_get_project, mock_add_comment):
        finding = self._finding("jira instance but no project", -1)
        self._link_jira_issue(finding)
        mock_get_instance.return_value = Mock(global_jira_sla_notification=False)

        sla_compute_and_notify()

        notified = self._notified_finding_ids(mock_create_notification)
        self.assertEqual(notified, [finding.id], msg=f"sla_breach notifications: {notified}")
        mock_add_comment.assert_not_called()

    @patch("dojo.notifications.helper.create_notification")
    def test_jira_only_notifies_findings_linked_to_a_jira_issue(self, mock_create_notification):
        self.system_settings(enable_notify_sla_jira_only=True)
        linked = self._finding("linked to JIRA", -1)
        self._finding("not linked to JIRA", -1)
        self._link_jira_issue(linked)

        with patch("dojo.jira.services.get_instance", return_value=None):
            sla_compute_and_notify()

        notified = self._notified_finding_ids(mock_create_notification)
        self.assertEqual(notified, [linked.id], msg=f"sla_breach notifications: {notified}")

    @patch("dojo.notifications.helper.create_notification")
    def test_finding_whose_test_was_deleted_mid_run_does_not_stop_the_rest(self, mock_create_notification):
        # The customer's KeyError: 'test' is how Django reports a finding whose Test row is gone.
        # Delete the Test after the chunk has been read and before its related rows are loaded,
        # which is what a test deleted while the run is in progress looks like.
        healthy = self._finding("healthy", -1)
        other_test = self.create_test(engagement=self.test.engagement, scan_type="SLA notify scan", title="deleted")
        orphan = self._finding("test deleted under it", -1)
        Finding.objects.filter(pk=orphan.pk).update(test=other_test)
        later = self._finding("healthy, after the orphan", -1)

        real_prefetch = django_query.prefetch_related_objects

        def prefetch(*args, **kwargs):
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM dojo_test WHERE id = %s", [other_test.id])
            return real_prefetch(*args, **kwargs)

        try:
            with patch("django.db.models.query.prefetch_related_objects", side_effect=prefetch):
                sla_compute_and_notify()
        finally:
            # the FK is deferred; re-point the orphan so the end-of-test constraint check passes
            with connection.cursor() as cursor:
                cursor.execute("UPDATE dojo_finding SET test_id = %s WHERE id = %s", [self.test.id, orphan.id])

        notified = self._notified_finding_ids(mock_create_notification)
        expected = sorted([healthy.id, later.id])
        self.assertEqual(notified, expected, msg=f"expected {expected} notified despite orphan {orphan.id}, got {notified}")

    @patch("dojo.notifications.helper.SLA_NOTIFY_CHUNK_SIZE", 1)
    @patch("dojo.notifications.helper.create_notification")
    def test_database_error_on_one_finding_does_not_poison_the_rest(self, mock_create_notification):
        # Inside a transaction (as here), one failed statement aborts it and every later query
        # fails too, including the fetch of the next chunk. Each finding needs its own savepoint.
        first = self._finding("first", -1)
        broken = self._finding("database error while evaluating", -1)
        last = self._finding("last", -1)

        original_get_sla_period = Finding.get_sla_period

        def get_sla_period(finding):
            if finding.id == broken.id:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1 / 0")
            return original_get_sla_period(finding)

        with patch.object(Finding, "get_sla_period", autospec=True, side_effect=get_sla_period):
            sla_compute_and_notify()

        notified = self._notified_finding_ids(mock_create_notification)
        expected = sorted([first.id, last.id])
        self.assertEqual(notified, expected, msg=f"expected {expected} notified despite a DB error on {broken.id}, got {notified}")

    @patch("dojo.notifications.helper.SLA_NOTIFY_CHUNK_SIZE", 1)
    @patch("dojo.notifications.helper.create_notification")
    def test_findings_read_before_a_failed_chunk_are_still_notified(self, mock_create_notification):
        first = self._finding("read before the failure", -1)
        self._finding("in the chunk that fails", -1)

        real_prefetch = django_query.prefetch_related_objects
        calls = {"n": 0}

        def prefetch(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 2:
                msg = "simulated lost connection while reading the next chunk"
                raise OperationalError(msg)
            return real_prefetch(*args, **kwargs)

        with patch("django.db.models.query.prefetch_related_objects", side_effect=prefetch):
            sla_compute_and_notify()

        notified = self._notified_finding_ids(mock_create_notification)
        self.assertEqual(notified, [first.id], msg=f"notifications collected before the failure must still go out, got {notified}")

    @patch("dojo.jira.services.add_simple_comment")
    @patch("dojo.jira.services.get_project")
    @patch("dojo.jira.services.get_instance")
    @patch("dojo.notifications.helper.create_notification")
    def test_failed_jira_comment_does_not_stop_the_rest(self, mock_create_notification, mock_get_instance, mock_get_project, mock_add_comment):
        first = self._finding("JIRA comment fails", -1)
        second = self._finding("JIRA comment works", -1)
        issues = {f.id: self._link_jira_issue(f) for f in (first, second)}
        mock_get_instance.return_value = Mock(global_jira_sla_notification=True)
        mock_get_project.return_value = Mock(product_jira_sla_notification=False)

        def add_comment(jira_instance, jira_issue, comment):
            if jira_issue.id == issues[first.id].id:
                msg = "simulated JIRA outage for one issue"
                raise RuntimeError(msg)

        mock_add_comment.side_effect = add_comment
        sla_compute_and_notify()

        notified = self._notified_finding_ids(mock_create_notification)
        self.assertEqual(notified, sorted([first.id, second.id]), msg=f"in-app notifications: {notified}")
        commented = sorted(call.args[1].id for call in mock_add_comment.call_args_list)
        self.assertEqual(commented, sorted(issues[f.id].id for f in (first, second)), msg=f"JIRA comment attempts: {commented}")
