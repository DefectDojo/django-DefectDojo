import datetime
from operator import itemgetter
from unittest.mock import Mock, patch

from django.db.models import Q
from django.test import TestCase
from django.utils import timezone

import dojo.risk_acceptance.helper as ra_helper
from dojo.jira.models import JIRA_Issue
from dojo.models import Engagement, Finding, Risk_Acceptance, System_Settings
from dojo.notifications import ticket_comments
from dojo.notifications.helper import sla_compute_and_notify
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures
from unittests.test_notifications_sla import SlaNotifyTestBase


class _Recorder:

    """A ticket comment handler that remembers every call, as (event, finding ids, texts by id, risk acceptance)."""

    def __init__(self):
        self.calls = []

    def __call__(self, event, findings, text, risk_acceptance=None):
        self.calls.append((
            event,
            [finding.id for finding in findings],
            {finding.id: ticket_comments.comment_text(text, finding) for finding in findings},
            risk_acceptance,
        ))


def _raising_handler(event, findings, text, risk_acceptance=None):
    msg = "simulated failure in a ticket comment handler"
    raise RuntimeError(msg)


class _IsolatedRegistry:

    """Every test starts with no handler and no link filter, and leaves the registry as it found it."""

    def isolate_registry(self):
        handlers, filters = list(ticket_comments._handlers), list(ticket_comments._link_filters)
        ticket_comments._handlers.clear()
        ticket_comments._link_filters.clear()

        def restore():
            ticket_comments._handlers[:] = handlers
            ticket_comments._link_filters[:] = filters

        self.addCleanup(restore)

    def record(self):
        recorder = _Recorder()
        ticket_comments.register_ticket_comment_handler(recorder)
        return recorder


class TestTicketCommentRegistry(_IsolatedRegistry, TestCase):

    def setUp(self):
        self.isolate_registry()

    def test_registering_a_handler_twice_calls_it_once(self):
        recorder = _Recorder()
        ticket_comments.register_ticket_comment_handler(recorder)
        ticket_comments.register_ticket_comment_handler(recorder)

        ticket_comments.dispatch_ticket_comments(ticket_comments.SLA_BREACHED, [Mock(id=1)], "text")

        self.assertEqual(len(recorder.calls), 1)

    def test_an_unregistered_handler_is_not_called(self):
        recorder = self.record()
        ticket_comments.unregister_ticket_comment_handler(recorder)
        ticket_comments.unregister_ticket_comment_handler(recorder)

        ticket_comments.dispatch_ticket_comments(ticket_comments.SLA_BREACHED, [Mock(id=1)], "text")

        self.assertEqual(recorder.calls, [])
        self.assertFalse(ticket_comments.has_ticket_comment_handlers())

    def test_an_empty_batch_calls_no_handler(self):
        recorder = self.record()

        ticket_comments.dispatch_ticket_comments(ticket_comments.SLA_BREACHED, [], "text")

        self.assertEqual(recorder.calls, [])

    def test_a_raising_handler_does_not_stop_the_next(self):
        ticket_comments.register_ticket_comment_handler(_raising_handler)
        recorder = self.record()

        with self.assertLogs("dojo.notifications.ticket_comments", "ERROR"):
            ticket_comments.dispatch_ticket_comments(ticket_comments.SLA_BREACHED, [Mock(id=7)], "text")

        self.assertEqual(recorder.calls, [(ticket_comments.SLA_BREACHED, [7], {7: "text"}, None)])

    def test_comment_text_reads_one_text_or_one_per_finding(self):
        finding = Mock(id=3)

        self.assertEqual(ticket_comments.comment_text("same for all", finding), "same for all")
        self.assertEqual(ticket_comments.comment_text({3: "own", 4: "other"}, finding), "own")
        self.assertEqual(ticket_comments.comment_text({4: "other"}, finding), "")

    def test_link_filters_are_or_ed_and_a_broken_one_is_left_out(self):
        def broken():
            msg = "simulated broken link filter"
            raise RuntimeError(msg)

        self.assertIsNone(ticket_comments.ticket_link_filter())
        ticket_comments.register_ticket_link_filter(lambda: Q(id=1))
        ticket_comments.register_ticket_link_filter(lambda: None)
        ticket_comments.register_ticket_link_filter(broken)
        second = lambda: Q(id=2)  # noqa: E731
        ticket_comments.register_ticket_link_filter(second)
        ticket_comments.register_ticket_link_filter(second)

        with self.assertLogs("dojo.notifications.ticket_comments", "ERROR"):
            combined = ticket_comments.ticket_link_filter()

        self.assertEqual(combined, Q(id=1) | Q(id=2))
        ticket_comments.unregister_ticket_link_filter(second)
        ticket_comments.unregister_ticket_link_filter(second)
        with self.assertLogs("dojo.notifications.ticket_comments", "ERROR"):
            self.assertEqual(ticket_comments.ticket_link_filter(), Q(id=1))


@versioned_fixtures
class TestSlaTicketComments(_IsolatedRegistry, SlaNotifyTestBase):

    def setUp(self):
        super().setUp()
        self.isolate_registry()

    @staticmethod
    def _titles(mock_create_notification):
        return {
            call.kwargs["finding"].id: call.kwargs["title"]
            for call in mock_create_notification.call_args_list
            if call.kwargs.get("event") == "sla_breach"
        }

    @patch("dojo.notifications.helper.create_notification")
    def test_each_sla_kind_reaches_the_handlers_with_each_findings_title(self, mock_create_notification):
        recorder = self.record()
        breached = [self._finding("breached one", -1), self._finding("breached two", -1)]
        breaching = self._finding("breaching today", 0)
        prebreach = self._finding("pre-breach", 2)

        sla_compute_and_notify()

        calls = sorted(recorder.calls, key=itemgetter(0))
        expected = [
            (ticket_comments.SLA_BREACHED, sorted(f.id for f in breached), {
                f.id: f"Finding {f.id} - SLA breached by 1 day! Overdue notice" for f in breached
            }, None),
            (ticket_comments.SLA_BREACHING, [breaching.id], {
                breaching.id: f"Finding {breaching.id} - SLA is breaching today",
            }, None),
            (ticket_comments.SLA_PREBREACH, [prebreach.id], {
                prebreach.id: f"Finding {prebreach.id} - SLA pre-breach warning - 2 day(s) left",
            }, None),
        ]
        calls = [(event, sorted(ids), texts, ra) for event, ids, texts, ra in calls]
        self.assertEqual(calls, expected, msg=f"handler calls: {calls}")
        # the comment is the notification's own title, as for the JIRA comment
        titles = self._titles(mock_create_notification)
        for _, _, texts, _ in calls:
            for finding_id, text in texts.items():
                self.assertEqual(text, titles[finding_id])

    @patch("dojo.notifications.helper.create_notification")
    def test_a_finding_past_the_post_breach_limit_gets_no_comment(self, mock_create_notification):
        recorder = self.record()
        finding = self._finding("breached long ago", -10)
        # mitigated keeps it in the query; sla_days_remaining() then counts from the mitigated date
        Finding.objects.filter(pk=finding.pk).update(mitigated=timezone.now() - datetime.timedelta(days=1))

        sla_compute_and_notify()

        self.assertEqual(recorder.calls, [])

    @patch("dojo.notifications.helper.create_notification")
    def test_exponential_backoff_skips_the_comment_with_the_notification(self, mock_create_notification):
        self.system_settings(enable_notify_sla_exponential_backoff=True)
        recorder = self.record()
        self._finding("breached 3 days ago, skipped", -3)
        kept = self._finding("breached 4 days ago, notified", -4)

        sla_compute_and_notify()

        self.assertEqual([(event, ids) for event, ids, _, _ in recorder.calls], [(ticket_comments.SLA_BREACHED, [kept.id])])

    @patch("dojo.jira.services.add_simple_comment")
    @patch("dojo.jira.services.get_project")
    @patch("dojo.jira.services.get_instance")
    @patch("dojo.notifications.helper.create_notification")
    def test_a_raising_handler_stops_neither_the_notification_nor_the_jira_comment(self, mock_create_notification, mock_get_instance, mock_get_project, mock_add_comment):
        ticket_comments.register_ticket_comment_handler(_raising_handler)
        recorder = self.record()
        finding = self._finding("linked to JIRA", -1)
        issue = JIRA_Issue.objects.create(finding=finding, jira_id=f"{finding.id}", jira_key=f"SLA-{finding.id}")
        mock_get_instance.return_value = Mock(global_jira_sla_notification=True)
        mock_get_project.return_value = Mock(product_jira_sla_notification=False)

        with self.assertLogs("dojo.notifications.ticket_comments", "ERROR"):
            sla_compute_and_notify()

        self.assertEqual(self._notified_finding_ids(mock_create_notification), [finding.id])
        self.assertEqual([call.args[1].id for call in mock_add_comment.call_args_list], [issue.id])
        self.assertEqual([ids for _, ids, _, _ in recorder.calls], [[finding.id]])

    @patch("dojo.notifications.helper.create_notification")
    def test_jira_only_also_notifies_findings_matched_by_a_registered_link_filter(self, mock_create_notification):
        self.system_settings(enable_notify_sla_jira_only=True)
        recorder = self.record()
        linked = self._finding("linked to JIRA", -1)
        elsewhere = self._finding("tracked in another ticket system", -1)
        self._finding("not tracked anywhere", -1)
        JIRA_Issue.objects.create(finding=linked, jira_id=f"{linked.id}", jira_key=f"SLA-{linked.id}")
        ticket_comments.register_ticket_link_filter(lambda: Q(id=elsewhere.id))

        with patch("dojo.jira.services.get_instance", return_value=None):
            sla_compute_and_notify()

        expected = sorted([linked.id, elsewhere.id])
        self.assertEqual(self._notified_finding_ids(mock_create_notification), expected)
        self.assertEqual([sorted(ids) for _, ids, _, _ in recorder.calls], [expected])

    @patch("dojo.notifications.helper.create_notification")
    def test_jira_only_without_a_link_filter_is_unchanged(self, mock_create_notification):
        self.system_settings(enable_notify_sla_jira_only=True)
        linked = self._finding("linked to JIRA", -1)
        self._finding("not linked", -1)
        JIRA_Issue.objects.create(finding=linked, jira_id=f"{linked.id}", jira_key=f"SLA-{linked.id}")
        ticket_comments.register_ticket_link_filter(lambda: None)

        with patch("dojo.jira.services.get_instance", return_value=None):
            sla_compute_and_notify()

        self.assertEqual(self._notified_finding_ids(mock_create_notification), [linked.id])


@versioned_fixtures
class TestRiskAcceptanceTicketComments(_IsolatedRegistry, DojoTestCase):

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.isolate_registry()
        self.engagement = Engagement.objects.get(id=1)
        # findings no risk acceptance in the fixture holds, so each test decides every membership
        self.findings = list(
            Finding.objects.filter(test__engagement=self.engagement, risk_acceptance__isnull=True).order_by("id")[:3],
        )
        self.assertEqual(len(self.findings), 3, msg="setup: the fixture has too few free findings on engagement 1")

    def _risk_acceptance(self, findings, **kwargs):
        risk_acceptance = Risk_Acceptance.objects.create(
            name="Ticket comment acceptance",
            owner=self.get_test_admin(),
            expiration_date=timezone.now() + datetime.timedelta(days=30),
            **kwargs,
        )
        risk_acceptance.accepted_findings.set(findings)
        Finding.objects.filter(id__in=[f.id for f in findings]).update(active=False, risk_accepted=True)
        self.engagement.risk_acceptance.add(risk_acceptance)
        return risk_acceptance

    @staticmethod
    def _about(recorder, risk_acceptance):
        return [call for call in recorder.calls if call[3] == risk_acceptance]

    def test_adding_a_finding_comments_accepted(self):
        risk_acceptance = self._risk_acceptance(self.findings[:1])
        recorder = self.record()

        with self.captureOnCommitCallbacks(execute=True):
            ra_helper.add_findings_to_risk_acceptance(None, risk_acceptance, [self.findings[1]])

        text = ra_helper.accepted_message_creator(risk_acceptance)
        self.assertEqual(recorder.calls, [
            (ticket_comments.RISK_ACCEPTANCE_ACCEPTED, [self.findings[1].id], {self.findings[1].id: text}, risk_acceptance),
        ])

    def test_removing_a_finding_comments_unaccepted(self):
        risk_acceptance = self._risk_acceptance(self.findings[:2])
        recorder = self.record()

        ra_helper.remove_finding_from_risk_acceptance(None, risk_acceptance, self.findings[0])

        text = ra_helper.unaccepted_message_creator(risk_acceptance)
        self.assertEqual(recorder.calls, [
            (ticket_comments.RISK_ACCEPTANCE_UNACCEPTED, [self.findings[0].id], {self.findings[0].id: text}, risk_acceptance),
        ])

    def test_expiring_comments_expired_and_reinstating_comments_reinstated(self):
        risk_acceptance = self._risk_acceptance(self.findings[:2])
        member_ids = [f.id for f in self.findings[:2]]
        recorder = self.record()

        ra_helper.expire_now(risk_acceptance)

        expired_text = ra_helper.expiration_message_creator(risk_acceptance)
        self.assertEqual(
            [(event, sorted(ids), texts, ra) for event, ids, texts, ra in recorder.calls],
            [(ticket_comments.RISK_ACCEPTANCE_EXPIRED, member_ids, dict.fromkeys(member_ids, expired_text), risk_acceptance)],
        )

        recorder.calls.clear()
        with self.captureOnCommitCallbacks(execute=True):
            ra_helper.reinstate(risk_acceptance, risk_acceptance.expiration_date)

        reinstated_text = ra_helper.reinstation_message_creator(risk_acceptance)
        self.assertEqual(
            [(event, sorted(ids), texts, ra) for event, ids, texts, ra in recorder.calls],
            [(ticket_comments.RISK_ACCEPTANCE_REINSTATED, member_ids, dict.fromkeys(member_ids, reinstated_text), risk_acceptance)],
        )

    def test_the_expiration_job_comments_the_warning(self):
        system_settings = System_Settings.objects.get(no_cache=True)
        system_settings.risk_acceptance_notify_before_expiration = 10
        system_settings.save()
        risk_acceptance = self._risk_acceptance(self.findings[:2])
        Risk_Acceptance.objects.filter(pk=risk_acceptance.pk).update(expiration_date=timezone.now() + datetime.timedelta(days=5))
        risk_acceptance.refresh_from_db()
        member_ids = [f.id for f in self.findings[:2]]
        recorder = self.record()

        ra_helper.expiration_handler()

        text = ra_helper.expiration_warning_message_creator(risk_acceptance, 10)
        self.assertEqual(
            [(event, sorted(ids), texts) for event, ids, texts, _ in self._about(recorder, risk_acceptance)],
            [(ticket_comments.RISK_ACCEPTANCE_EXPIRATION_WARNING, member_ids, dict.fromkeys(member_ids, text))],
        )

    def test_a_single_finding_comment_has_no_risk_acceptance(self):
        recorder = self.record()
        finding = self.findings[0]

        ra_helper.post_jira_comment(finding, ra_helper.accepted_message_creator)
        ra_helper.post_jira_comment(finding, ra_helper.unaccepted_message_creator)
        ra_helper.post_jira_comment(None, ra_helper.unaccepted_message_creator)

        self.assertEqual(recorder.calls, [
            (ticket_comments.RISK_ACCEPTANCE_ACCEPTED, [finding.id], {finding.id: "Finding has been risk accepted"}, None),
            (ticket_comments.RISK_ACCEPTANCE_UNACCEPTED, [finding.id], {finding.id: "Finding is no longer risk accepted"}, None),
        ])

    def test_an_unknown_message_creator_is_not_sent_to_the_handlers(self):
        recorder = self.record()

        ra_helper.post_jira_comments(self._risk_acceptance(self.findings[:1]), self.findings[:1], lambda *_: "custom")

        self.assertEqual(recorder.calls, [])

    @patch("dojo.risk_acceptance.helper.jira_services")
    def test_a_message_creator_that_raises_is_logged_and_skipped(self, jira):
        jira.get_project.return_value = None
        recorder = self.record()
        risk_acceptance = self._risk_acceptance(self.findings[:1])

        with (
            patch.object(ra_helper, "accepted_message_creator", side_effect=RuntimeError("no engagement")) as creator,
            self.assertLogs("dojo.risk_acceptance.helper", "ERROR"),
        ):
            ra_helper.post_jira_comments(risk_acceptance, self.findings[:1], creator)

        self.assertEqual(recorder.calls, [])

    @patch("dojo.risk_acceptance.helper.jira_services")
    def test_a_raising_handler_does_not_stop_the_jira_comment(self, jira):
        jira.get_project.return_value = Mock(risk_acceptance_expiration_notification=True)
        jira.get_instance.return_value = Mock(name="jira instance")
        finding = self.findings[0]
        issue = JIRA_Issue.objects.create(finding=finding, jira_id=f"{finding.id}", jira_key=f"RA-{finding.id}")
        risk_acceptance = self._risk_acceptance([finding])
        ticket_comments.register_ticket_comment_handler(_raising_handler)
        recorder = self.record()

        with self.assertLogs("dojo.notifications.ticket_comments", "ERROR"):
            ra_helper.post_jira_comments(risk_acceptance, risk_acceptance.accepted_findings.all(), ra_helper.unaccepted_message_creator)

        self.assertEqual([call.args[1].id for call in jira.add_simple_comment.call_args_list], [issue.id])
        self.assertEqual([ids for _, ids, _, _ in recorder.calls], [[finding.id]])

    @patch("dojo.risk_acceptance.helper.jira_services")
    def test_without_a_handler_nothing_extra_is_built(self, jira):
        jira.get_project.return_value = None
        creator = Mock(return_value="text")

        ra_helper.post_jira_comments(self._risk_acceptance(self.findings[:1]), self.findings[:1], creator)
        ra_helper.post_jira_comment(self.findings[0], creator)

        creator.assert_not_called()
