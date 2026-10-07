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

import crum
from django.core import mail
from django.core.mail.backends import locmem
from django.db import connection
from django.template import Context, Template
from django.template.loader import render_to_string
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import translation

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
from dojo.notifications.helper import (
    AlertNotificationManger,
    EmailNotificationManger,
    NotificationManager,
    create_notification,
)
from dojo.notifications.render_cache import MAX_VARIANTS, NotificationRenderCache
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


# Regression: at 15,000 recipients one scan_added notification spent about 11 minutes in the
# worker rendering the same templates once per recipient per channel and opening one mail
# connection per message.


class _CountingMailBackend(locmem.EmailBackend):

    """The locmem backend, counting connections the way an SMTP server would see them."""

    created = 0
    closed = 0
    fail_for: tuple = ()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        type(self).created += 1

    def close(self):
        type(self).closed += 1
        return super().close()

    def send_messages(self, messages):
        for message in messages:
            if any(address in self.fail_for for address in message.to):
                msg = "connection dropped"
                raise OSError(msg)
        return super().send_messages(messages)


COUNTING_BACKEND = f"{__name__}._CountingMailBackend"

# Names chosen to exercise escaping and the empty-name branch of the templates.
_NAMES = [("Ann", "Lee"), ("O'Brien", "<b>&amp;</b>"), ("", ""), ("Zoë", "Ångström"), ("a & b", '"quoted"')]


def _recipient(username, *, event="scan_added", channels=("alert", "mail"), name=("", "")):
    user = Dojo_User.objects.create(
        username=username, email=f"{username}@example.com", is_superuser=True, is_staff=True,
        first_name=name[0], last_name=name[1],
    )
    row = Notifications.objects.get(user=user, product__isnull=True)
    setattr(row, event, list(channels))
    row.save()
    return user


def _scan_added_kwargs():
    test = Test.objects.first()
    findings = list(Finding.objects.filter(test=test)[:3])
    return {
        "event": "scan_added",
        "title": "Created/Updated 3 findings",
        "finding_count": len(findings),
        "test": test,
        "engagement": test.engagement,
        "product": test.engagement.product,
        "findings_new": findings,
        "findings_mitigated": findings[:1],
        "findings_reactivated": [],
        "findings_untouched": [],
        "findings_new_duplicate": [],
        "findings_reactivated_duplicate": [],
        "findings_untouched_duplicate": [],
        "url": reverse("view_test", args=(test.id,)),
        "url_api": reverse("test-detail", args=(test.id,)),
    }


def _delivered(alerts_since):
    """Everything each recipient got, keyed by recipient and channel."""
    got = {}
    for alert in Alerts.objects.filter(id__gt=alerts_since).select_related("user_id").order_by("id"):
        got.setdefault(f"alert:{getattr(alert.user_id, 'username', None)}", []).append(
            (alert.title, alert.description, alert.url, alert.icon, alert.source),
        )
    for message in mail.outbox:
        got.setdefault(f"mail:{','.join(message.to)}", []).append(
            (message.subject, message.body, message.from_email, message.content_subtype, message.extra_headers),
        )
    return got


def _render_directly(_cache, _owner, _event, _notification_type, context, render):
    """NotificationRenderCache.render with the cache taken out: one render per recipient."""
    return render(context)


def _last_alert_id():
    return Alerts.objects.order_by("-id").values_list("id", flat=True).first() or 0


@versioned_fixtures
@override_settings(EMAIL_BACKEND=EMAIL_BACKEND)
class TestNotificationRenderedOncePerTemplate(DojoTestCase):

    """
    A fan-out renders each channel's template once, not once per recipient, and every
    recipient still gets exactly the message a render of their own would produce.
    """

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        system_settings = System_Settings.objects.get(no_cache=True)
        system_settings.enable_mail_notifications = True
        system_settings.save()
        mail.outbox = []

    def _notify(self, kwargs):
        # A product-scoped notification goes to the users authorized for the product as
        # seen by the user who caused it, as in the import request.
        with crum.impersonate(Dojo_User.objects.get(username="admin")):
            create_notification(**kwargs)

    def _renders(self):
        mail.outbox = []
        with patch("dojo.notifications.helper.render_to_string", wraps=render_to_string) as rendered:
            self._notify(_scan_added_kwargs())
        return rendered.call_count, len(mail.outbox)

    def test_renders_do_not_grow_with_recipients(self):
        n = 6
        for i in range(n):
            _recipient(f"render-a-{i}", name=("First", f"Last{i}"))
        small_renders, small_mails = self._renders()
        for i in range(n):
            _recipient(f"render-b-{i}", name=("First", f"Other{i}"))
        large_renders, large_mails = self._renders()

        self.assertEqual(large_mails - small_mails, n, "every added recipient still gets their mail")
        self.assertEqual(
            large_renders, small_renders,
            f"template renders grew from {small_renders} to {large_renders} for {n} more recipients",
        )
        # The mail template once and the alert fallback (scan_added has no alert template, so
        # the lookup fails and other.tpl renders) once: per notification, not per recipient.
        self.assertLessEqual(large_renders, 4)

    def test_each_recipient_gets_the_message_a_render_of_their_own_produces(self):
        for i, name in enumerate(_NAMES):
            _recipient(f"same-{i}", name=name)

        kwargs = _scan_added_kwargs()
        since = _last_alert_id()
        mail.outbox = []
        with patch.object(NotificationRenderCache, "render", _render_directly):
            self._notify(kwargs)
        uncached = _delivered(since)

        since = _last_alert_id()
        mail.outbox = []
        self._notify(kwargs)
        cached = _delivered(since)

        ours = [key for key in uncached if "same-" in key]
        self.assertEqual(len(ours), 2 * len(_NAMES), sorted(uncached))
        for key in sorted(set(uncached) | set(cached)):
            with self.subTest(recipient=key):
                self.assertEqual(cached.get(key), uncached.get(key))
        # The names really are in the mails, escaped as the template escapes them.
        bodies = "".join(m.body for m in mail.outbox)
        self.assertIn("O&#x27;Brien &lt;b&gt;&amp;amp;&lt;/b&gt;", bodies)
        self.assertIn("Zoë Ångström", bodies)


@versioned_fixtures
@override_settings(EMAIL_BACKEND=COUNTING_BACKEND)
class TestNotificationMailConnection(DojoTestCase):

    """A fan-out's mails share one connection per batch instead of one each."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        system_settings = System_Settings.objects.get(no_cache=True)
        system_settings.enable_mail_notifications = True
        system_settings.save()
        mail.outbox = []
        _CountingMailBackend.created = 0
        _CountingMailBackend.closed = 0
        _CountingMailBackend.fail_for = ()

    def _send(self):
        mail.outbox = []
        _CountingMailBackend.created = 0
        _CountingMailBackend.closed = 0
        create_notification(event="other", title="t", description="d", url="/alerts")

    def test_one_connection_for_all_recipients(self):
        for i in range(7):
            _recipient(f"conn-{i}", event="other", channels=("mail",))
        self._send()
        self.assertGreaterEqual(len(mail.outbox), 7)
        self.assertEqual(_CountingMailBackend.created, 1, f"{len(mail.outbox)} mails")
        self.assertEqual(_CountingMailBackend.closed, 1, "the shared connection is closed when the fan-out ends")

    def test_connection_is_replaced_after_each_batch(self):
        for i in range(7):
            _recipient(f"conn-{i}", event="other", channels=("mail",))
        with patch("dojo.notifications.helper.MAIL_MESSAGES_PER_CONNECTION", 3):
            self._send()
        sent = len(mail.outbox)
        self.assertEqual(_CountingMailBackend.created, -(-sent // 3), f"{sent} mails, 3 per connection")
        self.assertEqual(_CountingMailBackend.closed, _CountingMailBackend.created)

    def test_a_failed_send_reconnects_and_the_rest_still_go_out(self):
        for i in range(4):
            _recipient(f"conn-{i}", event="other", channels=("mail",))
        _CountingMailBackend.fail_for = ("conn-1@example.com",)
        failures_before = Alerts.objects.filter(source="Email Notification").count()
        self._send()
        delivered = sorted(a for m in mail.outbox for a in m.to if a.startswith("conn-"))
        self.assertEqual(delivered, ["conn-0@example.com", "conn-2@example.com", "conn-3@example.com"])
        self.assertEqual(_CountingMailBackend.created, 2, "the failed connection is dropped and a new one opened")
        superusers = Dojo_User.objects.filter(is_superuser=True).count()
        self.assertEqual(
            Alerts.objects.filter(source="Email Notification").count() - failures_before, superusers,
            "the failure is still reported to every superuser",
        )

    def test_a_message_sent_on_its_own_keeps_its_own_connection(self):
        user = _recipient("conn-solo", event="other", channels=("mail",))
        EmailNotificationManger().send_mail_notification("other", user=user, title="t", url="/alerts")
        EmailNotificationManger().send_mail_notification("other", user=user, title="t", url="/alerts")
        self.assertEqual(_CountingMailBackend.created, 2)
        self.assertEqual(len(mail.outbox), 2)


@versioned_fixtures
class TestWebhookOwnersReadOnce(DojoTestCase):

    """Recipients who chose the webhooks channel but own no endpoint cost no query each."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        system_settings = System_Settings.objects.get(no_cache=True)
        system_settings.enable_webhooks_notifications = True
        system_settings.save()

    def _dispatch(self):
        with CaptureQueriesContext(connection) as ctx:
            create_notification(event="other", title="t", description="d", url="/alerts")
        return [q["sql"] for q in ctx.captured_queries]

    def test_queries_do_not_grow_with_webhook_recipients(self):
        n = 4
        for i in range(n):
            _recipient(f"hook-a-{i}", event="other", channels=("webhooks",))
        self._dispatch()
        small = self._dispatch()
        for i in range(n):
            _recipient(f"hook-b-{i}", event="other", channels=("webhooks",))
        large = self._dispatch()
        self.assertEqual(len(large), len(small), "\n".join(q[:150] for q in large))


class TestNotificationRenderCache(DojoTestCase):

    """
    The cache reproduces a direct render for every recipient, whatever the template does
    with the recipient, and only reuses a render where that is provably the same text.
    """

    USERS = [
        ("cache-ann", "Ann", "Lee", "ann@example.com"),
        ("cache-ann2", "Ann", "Lee", "ann2@example.com"),
        ("cache-html", "<script>", "&amp; 'x'", ""),
        ("cache-empty", "", "", ""),
        ("cache-zoe", "Zoë", "Ångström", "zoe@example.com"),
    ]

    # (template, reused across recipients): reused means rendered at most once per variant.
    TEMPLATES = [
        ("Hello {{ user.get_full_name }}, {{ title }}", True),
        ("{% autoescape off %}{{ user.get_full_name }}{% endautoescape %}", True),
        ("{% if user.get_full_name %}Hi {{ user.get_full_name }}{% else %}Hi there{% endif %}", True),
        ("{% with n=user.get_full_name %}{{ n }}|{{ n }}{% endwith %}", True),
        ("{{ user.email|default:'no mail' }}", True),
        ("{% load i18n %}{% blocktranslate with n=user.get_full_name %}Hello {{ n }}{% endblocktranslate %}", True),
        ("{{ user }}", True),
        ("{{ user.usercontactinfo.title }}-{{ user.missing_attribute }}", True),
        ("{% if user %}yes{% endif %}{% if not user.is_superuser %}plain{% endif %}", True),
        ("{{ user.get_full_name|upper }}", False),
        ("{{ user.get_full_name|safe }}", False),
        ("{{ user.get_full_name|escape }}", False),
        ("{% filter upper %}{{ user.get_full_name }}{% endfilter %}", False),
        ("{% if user.get_full_name == 'Ann Lee' %}match{% endif %}", False),
        ("{{ user.username|length }}", False),
        ("{{ user.get_full_name|truncatechars:4 }}", False),
        ("{{ user.get_full_name|slice:':2' }}", False),
        ("{{ user.get_full_name|addslashes }}", False),
        ("{{ user.get_full_name|cut:'n' }}", False),
        ("{{ user.id }} {{ user.pk }}", False),
        ("{% for c in user.username %}{{ c }}{% endfor %}", False),
        ("{% if user in users %}listed{% endif %}", False),
        ("{% spaceless %}<p> {{ user.get_full_name }} </p>{% endspaceless %}", False),
    ]

    @classmethod
    def setUpTestData(cls):
        cls.users = [
            Dojo_User.objects.create(username=u, first_name=f, last_name=last, email=e)
            for u, f, last, e in cls.USERS
        ]

    def _render_each(self, source, cache, users, **extra):
        template = Template(source)
        calls = []

        def render(context):
            calls.append(context["user"])
            return template.render(Context(context))

        results = []
        # The shared context is the same objects for every recipient, as in a fan-out.
        shared = {"title": "<i>title</i>", "users": self.users[:1], **extra}
        for user in users:
            context = {"user": user, **shared}
            direct = template.render(Context(dict(context)))
            results.append((user.username, direct, cache.render(None, "other", "mail", context, render)))
        return results, len(calls)

    def test_every_recipient_gets_the_direct_render(self):
        for source, reusable in self.TEMPLATES:
            with self.subTest(template=source):
                cache = NotificationRenderCache()
                results, renders = self._render_each(source, cache, self.users)
                for username, direct, cached in results:
                    self.assertEqual(cached, direct, f"{username}: {source}")
                if reusable:
                    self.assertLess(renders, len(self.users), f"{source} rendered {renders} times")
                    self.assertGreater(cache.reuses, 0)
                else:
                    self.assertEqual(cache.reuses, 0, source)

    def test_a_render_is_not_reused_across_languages(self):
        cache = NotificationRenderCache()
        source = "{% load i18n %}{% translate 'Hello' %} {{ user.get_full_name }} {% get_current_language as l %}{{ l }}"
        for language in ("en", "de", "en"):
            with self.subTest(language=language), translation.override(language):
                results, _ = self._render_each(source, cache, self.users[:2])
                for username, direct, cached in results:
                    self.assertEqual(cached, direct, username)

    def test_a_render_is_not_reused_across_shared_context(self):
        cache = NotificationRenderCache()
        source = "{{ title }} {{ user.get_full_name }}"
        first, _ = self._render_each(source, cache, self.users[:1], title="one")
        second, _ = self._render_each(source, cache, self.users[:1], title="two")
        self.assertIn("one", first[0][2])
        self.assertIn("two", second[0][2])

    def test_variants_are_bounded(self):
        cache = NotificationRenderCache()
        users = [Dojo_User.objects.create(username=f"cache-many-{i}") for i in range(MAX_VARIANTS + 3)]
        results, renders = self._render_each("{{ user.id }}", cache, users)
        for username, direct, cached in results:
            self.assertEqual(cached, direct, username)
        self.assertEqual(renders, len(users))
