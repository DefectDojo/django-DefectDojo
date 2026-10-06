"""
Notification fan-out costs a bounded number of queries, whatever the recipient count.

Regression: one notification to R recipients cost several queries per recipient. Each
in-app alert was its own INSERT, each enabled channel re-fetched the recipient and
rebuilt a whole manager (system notifications row, system settings) before sending,
and a channel failure wrote one fallback alert per superuser, each behind its own
foreign-key probe. On an instance with thousands of users that made one import's
``scan_added`` notification cost tens of thousands of queries, inside the import
request, because ``notify_scan_added`` called ``create_notification`` directly
instead of dispatching it like every other notification.
"""

from unittest.mock import patch

from django.core import mail
from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from dojo.importers.default_importer import DefaultImporter
from dojo.models import (
    Alerts,
    Development_Environment,
    Dojo_User,
    Finding,
    Notifications,
    System_Settings,
    Test,
)
from dojo.notifications.helper import AlertNotificationManger, NotificationManager, create_notification
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures

EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"


def _superuser(username, *, channels=("alert", "mail")):
    user = Dojo_User.objects.create(
        username=username, email=f"{username}@example.com", is_superuser=True, is_staff=True,
    )
    # The user-created signal seeds a global row; narrow it to what the test says.
    row = Notifications.objects.get(user=user, product__isnull=True)
    row.other = list(channels)
    row.save()
    return user


@versioned_fixtures
@override_settings(EMAIL_BACKEND=EMAIL_BACKEND)
class TestNotificationFanoutQueryCount(DojoTestCase):

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        system_settings = System_Settings.objects.get(no_cache=True)
        system_settings.enable_mail_notifications = True
        system_settings.save()

    def _dispatch(self):
        mail.outbox = []
        with CaptureQueriesContext(connection) as ctx:
            create_notification(event="other", title="fan-out", description="fan-out", url="/alerts")
        return len(ctx.captured_queries), [q["sql"][:150] for q in ctx.captured_queries]

    def test_queries_do_not_grow_with_recipients(self):
        n = 4
        for i in range(n):
            _superuser(f"fanout-a-{i}")
        self._dispatch()  # warm per-process caches
        small, _ = self._dispatch()
        small_mails = len(mail.outbox)

        for i in range(n):
            _superuser(f"fanout-b-{i}")
        large, sqls = self._dispatch()
        large_mails = len(mail.outbox)

        self.assertEqual(large_mails - small_mails, n, "every added recipient still gets their mail")
        self.assertEqual(
            large, small,
            f"queries grew from {small} to {large} for {n} more recipients:\n" + "\n".join(sqls),
        )

    def test_failure_fallback_alert_cost_does_not_grow_with_superusers(self):
        manager = AlertNotificationManger()
        for i in range(3):
            _superuser(f"fallback-a-{i}")
        with CaptureQueriesContext(connection) as small:
            manager._log_alert(RuntimeError("boom"), "Email Notification", title="t", url="/alerts")
        for i in range(3):
            _superuser(f"fallback-b-{i}")
        with CaptureQueriesContext(connection) as large:
            manager._log_alert(RuntimeError("boom"), "Email Notification", title="t", url="/alerts")
        self.assertEqual(
            len(large.captured_queries), len(small.captured_queries),
            "\n".join(q["sql"][:150] for q in large.captured_queries),
        )


@versioned_fixtures
@override_settings(EMAIL_BACKEND=EMAIL_BACKEND)
class TestNotificationFanoutBehaviour(DojoTestCase):

    """Same recipients, same channels, same alert content as one-at-a-time delivery."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        system_settings = System_Settings.objects.get(no_cache=True)
        system_settings.enable_mail_notifications = True
        system_settings.save()
        mail.outbox = []

    def test_each_recipient_gets_their_channels(self):
        both = _superuser("fanout-both")
        alert_only = _superuser("fanout-alert", channels=("alert",))
        mail_only = _superuser("fanout-mail", channels=("mail",))
        silent = _superuser("fanout-none", channels=())

        create_notification(
            event="other", title="Fan-out title", description="Fan-out body", url="/alerts", icon="bullseye",
        )

        ours = {both, alert_only, mail_only, silent}
        alerts = Alerts.objects.filter(user_id__in=ours)
        self.assertEqual(
            sorted(a.user_id.username for a in alerts), ["fanout-alert", "fanout-both"],
        )
        for alert in alerts:
            self.assertEqual(alert.title, "Fan-out title")
            self.assertEqual(alert.url, "/alerts")
            self.assertEqual(alert.icon, "bullseye")
            self.assertEqual(alert.source, "Other")
            self.assertIn("Fan-out body", alert.description)
            self.assertIsNotNone(alert.created)
        mailed = sorted(addr for m in mail.outbox for addr in m.to if addr.startswith("fanout-"))
        self.assertEqual(mailed, ["fanout-both@example.com", "fanout-mail@example.com"])

    def test_a_failing_alert_batch_falls_back_to_one_failure_alert_per_superuser(self):
        _superuser("fanout-x")
        superusers = Dojo_User.objects.filter(is_superuser=True).count()
        before = Alerts.objects.filter(source="Alert Notification").count()
        with patch("dojo.notifications.helper.Alerts.objects.bulk_create", side_effect=[RuntimeError("db down"), None]) as bulk:
            create_notification(event="other", title="t", description="d", url="/alerts")
        # one attempt for the notification's alerts, one for the failure alerts
        self.assertEqual(bulk.call_count, 2)
        fallback = bulk.call_args_list[1].args[0]
        self.assertEqual(len(fallback), superusers)
        self.assertTrue(all(a.source == "Alert Notification" for a in fallback))
        self.assertEqual(Alerts.objects.filter(source="Alert Notification").count(), before)

    def test_alert_persistence_success_is_unbuffered_outside_a_fanout(self):
        """A bare manager, as other callers construct it, still writes immediately."""
        admin = Dojo_User.objects.get(username="admin")
        before = Alerts.objects.count()
        AlertNotificationManger().send_alert_notification("other", user=admin, title="direct", url=reverse("alerts"))
        self.assertEqual(Alerts.objects.count(), before + 1)

    def test_one_bulk_write_per_notification(self):
        _superuser("fanout-nested")
        manager = NotificationManager()
        with patch.object(Alerts.objects, "bulk_create", wraps=Alerts.objects.bulk_create) as bulk:
            manager.create_notification(event="other", title="outer", description="d", url="/alerts")
        self.assertEqual(bulk.call_count, 1)


@versioned_fixtures
class TestScanAddedLeavesTheRequest(DojoTestCase):

    """notify_scan_added hands the fan-out to the worker with ids, not instances."""

    fixtures = ["dojo_testdata.json"]

    def _importer(self):
        test = Test.objects.first()
        importer = DefaultImporter(
            scan_type="ZAP Scan",
            engagement=test.engagement,
            environment=Development_Environment.objects.first(),
        )
        return importer, test

    @patch("dojo.importers.base_importer.dojo_dispatch_task")
    def test_request_dispatches_once_with_json_safe_kwargs(self, mock_dispatch):
        importer, test = self._importer()
        importer.deduplication_complete = True
        high = Finding(test=test, title="high", severity="High")
        high.save()
        low = Finding(test=test, title="low", severity="Low")
        low.save()

        with CaptureQueriesContext(connection) as ctx:
            importer.notify_scan_added(test, updated_count=2, new_findings=[low.id, high.id])

        mock_dispatch.assert_called_once()
        kwargs = mock_dispatch.call_args.kwargs
        self.assertEqual(kwargs["event"], "scan_added")
        self.assertEqual(kwargs["test_id"], test.id)
        self.assertEqual(kwargs["finding_count"], 2)
        # ordered by severity, as the template lists them
        self.assertEqual(kwargs["finding_ids"]["findings_new"], [high.id, low.id])
        for key, value in kwargs.items():
            self.assertNotIsInstance(value, (Finding, Test), key)
        # nothing in the request scales with recipients: no Notifications/auth_user reads
        self.assertFalse(
            any('"dojo_notifications"' in q["sql"] or 'FROM "auth_user"' in q["sql"] for q in ctx.captured_queries),
            "\n".join(q["sql"][:150] for q in ctx.captured_queries),
        )

    @patch("dojo.notifications.helper.create_notification")
    def test_worker_hydrates_the_findings_in_order(self, mock_create):
        from dojo.notifications.tasks import async_create_notification  # noqa: PLC0415

        _importer, test = self._importer()
        high = Finding(test=test, title="high", severity="High")
        high.save()
        low = Finding(test=test, title="low", severity="Low")
        low.save()

        async_create_notification.run(
            event="scan_added", title="t", test_id=test.id, finding_count=2,
            finding_ids={"findings_new": [high.id, low.id], "findings_mitigated": []},
        )

        kwargs = mock_create.call_args.kwargs
        self.assertEqual([f.id for f in kwargs["findings_new"]], [high.id, low.id])
        self.assertEqual(kwargs["findings_mitigated"], [])
        self.assertEqual(kwargs["test"], test)
        self.assertNotIn("finding_ids", kwargs)
