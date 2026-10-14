import datetime
from unittest.mock import Mock, patch

from django.db import connection
from django.db.models import query as django_query
from django.db.utils import DataError, OperationalError
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from dojo.authorization.roles_permissions import Roles
from dojo.jira.models import JIRA_Issue
from dojo.models import Dojo_User, Finding, Product_Member, Role, Test_Type, User
from dojo.notifications import helper as notifications_helper
from dojo.notifications.helper import sla_compute_and_notify
from dojo.notifications.models import Alerts, Notifications
from dojo.user.models import UserContactInfo
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


class _ManagerWithoutBatch:

    """A NOTIFICATION_MANAGER that predates batching: it only has create_notification."""

    calls: list = []

    def create_notification(self, event=None, **kwargs):
        _ManagerWithoutBatch.calls.append((event, kwargs.get("finding")))


def _raising_queryset_hook(findings):
    msg = "simulated broken FINDING_SLA_NOTIFY_QUERYSET_METHOD"
    raise RuntimeError(msg)


def _lazily_broken_queryset_hook(findings):
    # Valid to call; fails only once the query is compiled.
    return findings.select_related("no_such_relation")


#: Set by the test of FINDING_SLA_NOTIFY_QUERYSET_METHOD: the finding the hook below leaves out.
_HOOK_EXCLUDES = {"id": None, "calls": 0}


def _sla_notify_queryset_hook(findings):
    """Stands in for what a FINDING_SLA_PERIOD_METHOD provider would add to the run's query."""
    _HOOK_EXCLUDES["calls"] += 1
    return findings.exclude(id=_HOOK_EXCLUDES["id"])


@override_settings(SLA_NOTIFY_PRE_BREACH=3, SLA_NOTIFY_POST_BREACH=7)
class SlaNotifyTestBase(DojoTestCase):

    """One product with findings pinned at chosen distances from their SLA deadline."""

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


# Regression: the daily SLA task ended the whole run at the first finding that raised, so no
# SLA notification went out for any finding, and it loaded every open finding into memory.
@versioned_fixtures
class TestSlaComputeAndNotify(SlaNotifyTestBase):

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


# The notifications of one SLA run go out through one manager: recipients are resolved once per
# product and alerts are written in batches, instead of all of that once per finding.
@versioned_fixtures
class TestSlaNotificationBatching(SlaNotifyTestBase):

    def setUp(self):
        super().setUp()
        Alerts.objects.all().delete()
        # Every notification goes to the active superusers and, through the system notifications
        # row (whose user is None), to one more alert without a user.
        self.recipient_ids = {*User.objects.filter(is_superuser=True, is_active=True).values_list("id", flat=True), None}

    def _sla_alerts(self):
        return Alerts.objects.filter(title__contains="SLA breached")

    def test_query_count_does_not_grow_with_notified_findings(self):
        # Real notifications, nothing mocked: the per-finding cost used to be the system
        # notifications row, the product's recipients and an alert INSERT, every time.
        self._finding("one", -1)
        with CaptureQueriesContext(connection) as one:
            sla_compute_and_notify()

        for i in range(4):
            self._finding(f"more {i}", -1)
        Alerts.objects.all().delete()
        with CaptureQueriesContext(connection) as five:
            sla_compute_and_notify()

        def data_queries(ctx):
            return [q["sql"] for q in ctx.captured_queries if "SAVEPOINT" not in q["sql"]]

        self.assertEqual(
            len(data_queries(five)), len(data_queries(one)),
            msg=f"queries with 1 notified finding: {len(data_queries(one))}, with 5: {len(data_queries(five))}\n"
            + "\n".join(q[:160] for q in data_queries(five)),
        )
        self.assertEqual(self._sla_alerts().count(), 5 * len(self.recipient_ids))

    def test_every_finding_gets_its_own_alert_for_every_recipient(self):
        findings = [self._finding(f"finding {i}", -1) for i in range(3)]

        sla_compute_and_notify()

        got = sorted(((a.user_id_id or 0), a.title) for a in self._sla_alerts())
        expected = sorted(
            ((user_id or 0), f"Finding {f.id} - SLA breached by 1 day! Overdue notice")
            for f in findings for user_id in self.recipient_ids
        )
        self.assertEqual(got, expected)

    def test_recipients_are_resolved_per_product(self):
        # A reader of one product only must get that product's alerts, never the other's,
        # even though the recipients are now looked up once per product and reused.
        reader = User.objects.create_user(username="sla_batch_reader", password="not-a-real-secret")  # noqa: S106 - test fixture user
        Product_Member.objects.create(user=reader, product=self.test.engagement.product, role=Role.objects.get(id=Roles.Reader))
        self.test.engagement.product.authorized_users.add(Dojo_User.objects.get(pk=reader.pk))
        Notifications.objects.create(user=reader, sla_breach=["alert"])

        visible = self._finding("on the reader's product", -1)
        other_product = self.create_product("SLA notify other product")
        other_engagement = self.create_engagement("SLA notify other engagement", other_product)
        other_test = self.create_test(engagement=other_engagement, scan_type="SLA notify scan", title="other")
        hidden = self._finding("on another product", -1)
        Finding.objects.filter(pk=hidden.pk).update(test=other_test)

        sla_compute_and_notify()

        reader_titles = sorted(self._sla_alerts().filter(user_id=reader).values_list("title", flat=True))
        self.assertEqual(reader_titles, [f"Finding {visible.id} - SLA breached by 1 day! Overdue notice"], msg=f"reader alerts: {reader_titles}")
        for superuser_id in self.recipient_ids - {None}:
            superuser_findings = sorted(t.split(" ")[1] for t in self._sla_alerts().filter(user_id=superuser_id).values_list("title", flat=True))
            self.assertEqual(superuser_findings, sorted([str(visible.id), str(hidden.id)]))

    def test_one_bad_alert_row_does_not_lose_the_rest_of_its_batch(self):
        findings = [self._finding(f"finding {i}", -1) for i in range(4)]
        bad_title = f"Finding {findings[1].id} - "
        real_bulk_create = Alerts.objects.bulk_create

        def bulk_create(alerts, *args, **kwargs):
            if any(a.title.startswith(bad_title) for a in alerts):
                msg = "simulated bad alert row"
                raise DataError(msg)
            return real_bulk_create(alerts, *args, **kwargs)

        with patch.object(Alerts.objects, "bulk_create", side_effect=bulk_create):
            sla_compute_and_notify()

        notified = sorted({int(t.split(" ")[1]) for t in self._sla_alerts().values_list("title", flat=True)})
        expected = sorted(f.id for f in findings if f.id != findings[1].id)
        self.assertEqual(notified, expected, msg=f"findings with alerts: {notified}")

    @patch("dojo.notifications.helper.ALERT_BULK_CREATE_BATCH_SIZE", 3)
    def test_a_failing_notification_does_not_roll_back_alerts_written_for_others(self):
        # Alerts of several findings are written together. If that write happened inside the
        # savepoint of a finding that then fails, rolling it back would erase the others too.
        findings = [self._finding(f"finding {i}", -1) for i in range(4)]
        failing = findings[1]
        real_send = notifications_helper.AlertNotificationManger.send_alert_notification

        def send_alert_notification(manager, event, user=None, **kwargs):
            real_send(manager, event, user=user, **kwargs)
            finding = kwargs.get("finding")
            if event == "sla_breach" and finding is not None and finding.id == failing.id:
                msg = "simulated failure after this finding's alert was built"
                raise RuntimeError(msg)

        with patch.object(notifications_helper.AlertNotificationManger, "send_alert_notification", autospec=True, side_effect=send_alert_notification):
            sla_compute_and_notify()

        notified = {int(t.split(" ")[1]) for t in self._sla_alerts().values_list("title", flat=True)}
        missing = sorted({f.id for f in findings if f.id != failing.id} - notified)
        self.assertEqual(missing, [], msg=f"findings that lost their alerts: {missing}")

    def test_a_database_outage_costs_a_bounded_number_of_writes(self):
        # Retrying row by row is for one bad row. When every write fails the database is the
        # problem: the batch must give up after a few rows and report it once, not once per row.
        for i in range(4):
            self._finding(f"finding {i}", -1)
        fallback_writes = []

        def bulk_create(alerts, *args, **kwargs):
            if all(a.source == "Alert Notification" for a in alerts):
                fallback_writes.append(len(alerts))
                return alerts
            msg = "simulated database outage"
            raise OperationalError(msg)

        with patch.object(Alerts.objects, "bulk_create", side_effect=bulk_create) as bulk:
            sla_compute_and_notify()

        retries = notifications_helper.NotificationManager.MAX_CONSECUTIVE_ALERT_FAILURES
        self.assertEqual(bulk.call_count, 1 + retries + 1, msg="one batch INSERT, the single-row retries, one fallback")
        self.assertEqual(len(fallback_writes), 1, msg=f"fallback writes: {fallback_writes}")

    def test_the_system_notification_still_reaches_the_system_destination(self):
        # Regression: merging a superuser's notification settings returned the shared system row
        # itself and set its user to that superuser, so in a batch every later notification's
        # system-level copy went to the superuser instead of the system destination.
        Notifications.objects.filter(user__isnull=False).delete()
        findings = [self._finding(f"finding {i}", -1) for i in range(3)]

        sla_compute_and_notify()

        system_titles = sorted(
            self._sla_alerts().filter(user_id__isnull=True).values_list("title", flat=True),
        )
        expected = sorted(f"Finding {f.id} - SLA breached by 1 day! Overdue notice" for f in findings)
        self.assertEqual(system_titles, expected, msg=f"system-level alerts: {system_titles}")

    def test_a_notification_whose_every_row_fails_does_not_cost_the_others(self):
        # One notification's alerts sit next to each other in the batch. If they all fail (its
        # title, say), that is one bad notification, not a database outage, however many
        # recipients it has.
        for i in range(6):
            User.objects.create(username=f"sla_batch_superuser_{i}", is_superuser=True, is_active=True)
        bad = self._finding("a finding whose alerts cannot be written", -1)
        healthy = [self._finding(f"b healthy {i}", -1) for i in range(3)]
        bad_title = f"Finding {bad.id} - "
        real_bulk_create = Alerts.objects.bulk_create

        def bulk_create(alerts, *args, **kwargs):
            if any(a.title.startswith(bad_title) for a in alerts):
                msg = "simulated bad alert rows"
                raise DataError(msg)
            return real_bulk_create(alerts, *args, **kwargs)

        with patch.object(Alerts.objects, "bulk_create", side_effect=bulk_create):
            sla_compute_and_notify()

        notified = sorted({int(t.split(" ")[1]) for t in self._sla_alerts().values_list("title", flat=True)})
        self.assertEqual(notified, sorted(f.id for f in healthy), msg=f"findings with alerts: {notified}")

    @patch("dojo.notifications.helper.ALERT_BULK_CREATE_BATCH_SIZE", 3)
    def test_an_outage_is_bounded_for_the_whole_run_not_each_flush(self):
        # With small flushes the run writes its alerts many times. An outage must cost the same
        # number of write attempts however many findings the run has, and be reported once.
        def outage_run(findings):
            for i in range(findings):
                self._finding(f"finding {findings}-{i}", -1)
            fallback_writes = []

            def bulk_create(alerts, *args, **kwargs):
                if all(a.source == "Alert Notification" for a in alerts):
                    fallback_writes.append(len(alerts))
                    return alerts
                msg = "simulated database outage"
                raise OperationalError(msg)

            with patch.object(Alerts.objects, "bulk_create", side_effect=bulk_create) as bulk:
                sla_compute_and_notify()
            Finding.objects.filter(active=True).update(active=False)
            return bulk.call_count, fallback_writes

        small_attempts, small_fallbacks = outage_run(6)
        large_attempts, large_fallbacks = outage_run(12)

        self.assertEqual(large_attempts, small_attempts, msg=f"write attempts: 6 findings {small_attempts}, 12 findings {large_attempts}")
        self.assertEqual(len(small_fallbacks), 1, msg=f"fallback writes: {small_fallbacks}")
        self.assertEqual(len(large_fallbacks), 1, msg=f"fallback writes: {large_fallbacks}")

    def test_a_manager_without_batch_support_still_sends_every_notification(self):
        findings = [self._finding(f"finding {i}", -1) for i in range(2)]
        _ManagerWithoutBatch.calls = []

        with override_settings(NOTIFICATION_MANAGER=f"{__name__}._ManagerWithoutBatch"):
            sla_compute_and_notify()

        notified = sorted(f.id for event, f in _ManagerWithoutBatch.calls if event == "sla_breach")
        self.assertEqual(notified, sorted(f.id for f in findings))

    @patch("dojo.notifications.helper.SlackNotificationManger._post_slack_message")
    @patch("dojo.notifications.helper.SlackNotificationManger._get_slack_user_id", return_value="U123")
    def test_a_slack_user_id_is_looked_up_once_per_run(self, mock_lookup, mock_post):
        self.system_settings(enable_slack_notifications=True)
        slack_user = User.objects.create(username="sla_batch_slack", is_superuser=True, is_active=True)
        UserContactInfo.objects.update_or_create(user=slack_user, defaults={"slack_username": "slack@example.com", "slack_user_id": None})
        Notifications.objects.filter(user=slack_user).update(sla_breach=["slack"], sla_breach_combined=[])
        for i in range(3):
            self._finding(f"finding {i}", -1)

        sla_compute_and_notify()

        self.assertEqual(mock_lookup.call_count, 1, msg="the id found for the first notification is reused")
        self.assertGreaterEqual(mock_post.call_count, 3)


@versioned_fixtures
class TestSlaNotifyQuerysetHook(SlaNotifyTestBase):

    # A FINDING_SLA_PERIOD_METHOD can read more of each finding than the run loads (DefectDojo
    # Pro's reads a companion row). The companion setting lets it add that to the run's query, so
    # it arrives with each chunk instead of costing one query per finding.
    @patch("dojo.notifications.helper.create_notification")
    def test_the_run_reads_findings_through_the_configured_queryset_method(self, mock_create_notification):
        kept = self._finding("kept", -1)
        left_out = self._finding("left out by the hook", -1)
        _HOOK_EXCLUDES.update(id=left_out.id, calls=0)

        with override_settings(FINDING_SLA_NOTIFY_QUERYSET_METHOD=f"{__name__}._sla_notify_queryset_hook"):
            sla_compute_and_notify()

        self.assertEqual(_HOOK_EXCLUDES["calls"], 1)
        self.assertEqual(self._notified_finding_ids(mock_create_notification), [kept.id])

    @patch("dojo.notifications.helper.create_notification")
    def test_without_the_setting_the_run_is_unchanged(self, mock_create_notification):
        findings = [self._finding(f"finding {i}", -1) for i in range(2)]

        sla_compute_and_notify()

        self.assertEqual(self._notified_finding_ids(mock_create_notification), sorted(f.id for f in findings))

    @patch("dojo.notifications.helper.create_notification")
    def test_a_hook_that_raises_falls_back_to_the_plain_query(self, mock_create_notification):
        findings = [self._finding(f"finding {i}", -1) for i in range(2)]

        with override_settings(FINDING_SLA_NOTIFY_QUERYSET_METHOD=f"{__name__}._raising_queryset_hook"):
            sla_compute_and_notify()

        self.assertEqual(self._notified_finding_ids(mock_create_notification), sorted(f.id for f in findings))

    @patch("dojo.notifications.helper.create_notification")
    def test_a_misnamed_hook_falls_back_to_the_plain_query(self, mock_create_notification):
        findings = [self._finding(f"finding {i}", -1) for i in range(2)]

        with override_settings(FINDING_SLA_NOTIFY_QUERYSET_METHOD=f"{__name__}._no_such_hook"):
            sla_compute_and_notify()

        self.assertEqual(self._notified_finding_ids(mock_create_notification), sorted(f.id for f in findings))

    @patch("dojo.notifications.helper.create_notification")
    def test_a_hook_whose_query_cannot_compile_falls_back_to_the_plain_query(self, mock_create_notification):
        findings = [self._finding(f"finding {i}", -1) for i in range(2)]

        with override_settings(FINDING_SLA_NOTIFY_QUERYSET_METHOD=f"{__name__}._lazily_broken_queryset_hook"):
            sla_compute_and_notify()

        self.assertEqual(self._notified_finding_ids(mock_create_notification), sorted(f.id for f in findings))
