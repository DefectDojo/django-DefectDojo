import copy
import datetime
import logging
from unittest.mock import patch

from dateutil.relativedelta import relativedelta
from django.db.models import Q
from django.urls import reverse
from django.utils import timezone

# from unittest.mock import patch
from django.utils.datastructures import MultiValueDict
from django.utils.http import urlencode

# from unittest import skip
import dojo.risk_acceptance.helper as ra_helper
from dojo.models import Finding, Risk_Acceptance, System_Settings
from dojo.utils import get_system_setting
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures

logger = logging.getLogger(__name__)


@versioned_fixtures
class RiskAcceptanceTestUI(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    data_risk_accceptance = {
        "name": "Accept: Unit test",
        "accepted_findings": [72808],
        "recommendation": "A",
        "recommendation_details": "recommendation 1",
        "decision": "A",
        "decision_details": "it has been decided!",
        "accepted_by": "pointy haired boss",
        # 'path: (binary)
        "owner": 1,
        "expiration_date": "2021-07-15",
        "reactivate_expired": True,
    }

    data_remove_finding_from_ra = {
        "remove_finding": "Remove",
        "remove_finding_id": 666,
    }

    def __init__(self, *args, **kwargs):
        DojoTestCase.__init__(self, *args, **kwargs)

    def setUp(self):
        self.system_settings(enable_jira=True)
        self.client.force_login(self.get_test_admin())

    def add_risk_acceptance(self, eid, data_risk_accceptance, fid=None):

        args = (eid, fid) if fid else (eid,)

        response = self.client.post(reverse("add_risk_acceptance", args=args), data_risk_accceptance)
        self.assertEqual(302, response.status_code, response.content[:1000])
        return response

    def assert_all_active_not_risk_accepted(self, findings):
        if not all(finding.active for finding in findings):
            return False

        return bool(not any(finding.risk_accepted for finding in findings))

    def assert_all_inactive_risk_accepted(self, findings):
        if any(finding.active for finding in findings):
            return False

        return bool(all(finding.risk_accepted for finding in findings))

    def test_add_risk_acceptance_single_findings_accepted(self):
        ra_data = copy.copy(self.data_risk_accceptance)
        ra_data["accepted_findings"] = [2]
        ra_data["return_url"] = reverse("view_finding", args=(2, ))
        response = self.add_risk_acceptance(1, ra_data, 2)
        self.assertEqual("/finding/2", response.url)
        ra = Risk_Acceptance.objects.last()
        self.assert_all_active_not_risk_accepted(ra.accepted_findings.all())

    def test_add_risk_acceptance_multiple_findings_accepted(self):
        ra_data = copy.copy(self.data_risk_accceptance)
        ra_data["accepted_findings"] = [2, 3]
        response = self.add_risk_acceptance(1, ra_data)
        self.assertEqual("/engagement/1", response.url)
        ra = Risk_Acceptance.objects.last()
        self.assert_all_active_not_risk_accepted(ra.accepted_findings.all())

    def test_add_findings_to_risk_acceptance_findings_accepted(self):
        # create risk acceptance first
        self.test_add_risk_acceptance_multiple_findings_accepted()
        ra = Risk_Acceptance.objects.last()

        data_add_findings_to_ra = {
            "add_findings": "Add Selected Findings",
            "accepted_findings": [4, 5],
        }

        response = self.client.post(reverse("view_risk_acceptance", args=(1, ra.id)),
                    urlencode(MultiValueDict(data_add_findings_to_ra), doseq=True),
                    content_type="application/x-www-form-urlencoded")

        self.assertEqual(302, response.status_code, response.content[:1000])
        self.assert_all_inactive_risk_accepted(Finding.objects.filter(id__in=[2, 3, 4, 5]))

    def test_remove_findings_from_risk_acceptance_findings_active(self):
        # create risk acceptance first
        self.test_add_risk_acceptance_multiple_findings_accepted()

        data = copy.copy(self.data_remove_finding_from_ra)
        data["remove_finding_id"] = 2
        ra = Risk_Acceptance.objects.last()
        response = self.client.post(reverse("edit_risk_acceptance", args=(1, ra.id)), data)
        self.assertEqual(302, response.status_code, response.content[:1000])
        self.assert_all_active_not_risk_accepted(Finding.objects.filter(id=2))
        self.assert_all_inactive_risk_accepted(Finding.objects.filter(id=3))

    def test_remove_risk_acceptance_findings_active(self):
        self.test_add_risk_acceptance_multiple_findings_accepted()
        ra = Risk_Acceptance.objects.last()

        findings = ra.accepted_findings.all()

        data = {"id": ra.id}

        self.client.post(reverse("delete_risk_acceptance", args=(1, ra.id)), data)

        self.assert_all_active_not_risk_accepted(findings)
        self.assert_all_active_not_risk_accepted(Finding.objects.filter(test__engagement=1))

    def test_expire_risk_acceptance_findings_active(self):
        self.test_add_risk_acceptance_multiple_findings_accepted()
        ra = Risk_Acceptance.objects.last()
        # ra.reactivate_expired = True # default True
        # ra.save()

        findings = ra.accepted_findings.all()

        data = {"id": ra.id}

        self.client.post(reverse("expire_risk_acceptance", args=(1, ra.id)), data)

        ra.refresh_from_db()
        self.assert_all_active_not_risk_accepted(findings)
        self.assertEqual(ra.expiration_date.date(), timezone.now().date())
        self.assertEqual(ra.expiration_date_handled.date(), timezone.now().date())
        self.assertIsNone(ra.expiration_date_warned)

        self.assert_all_active_not_risk_accepted(Finding.objects.filter(test__engagement=1))
        # findings remain in (expired) risk acceptance
        self.assertTrue(all(finding in ra.accepted_findings.all() for finding in findings))

    def test_expire_risk_acceptance_findings_not_active(self):
        self.test_add_risk_acceptance_multiple_findings_accepted()
        ra = Risk_Acceptance.objects.last()
        ra.reactivate_expired = False
        ra.save()

        findings = ra.accepted_findings.all()

        data = {"id": ra.id}

        self.client.post(reverse("expire_risk_acceptance", args=(1, ra.id)), data)

        ra.refresh_from_db()
        # no reactivation on expiry
        self.assert_all_inactive_risk_accepted(findings)
        self.assertEqual(ra.expiration_date.date(), timezone.now().date())
        self.assertEqual(ra.expiration_date_handled.date(), timezone.now().date())
        self.assertIsNone(ra.expiration_date_warned)

        self.assert_all_active_not_risk_accepted(Finding.objects.filter(test__engagement=1).filter(~Q(id=2)))
        # findings remain in (expired) risk acceptance
        self.assertTrue(all(finding in ra.accepted_findings.all() for finding in findings))

    def test_expire_risk_acceptance_sla_not_reset(self):
        self.test_add_risk_acceptance_multiple_findings_accepted()
        ra = Risk_Acceptance.objects.last()
        # ra.restart_sla_expired = False # default is False
        # ra.save()

        findings = ra.accepted_findings.all()

        data = {"id": ra.id}

        self.client.post(reverse("expire_risk_acceptance", args=(1, ra.id)), data)

        ra.refresh_from_db()

        self.assertTrue(all(finding.sla_start_date != timezone.now().date() for finding in findings))

    def test_expire_risk_acceptance_sla_reset(self):
        self.test_add_risk_acceptance_multiple_findings_accepted()
        ra = Risk_Acceptance.objects.last()
        ra.restart_sla_expired = True
        ra.save()

        findings = ra.accepted_findings.all()

        data = {"id": ra.id}

        self.client.post(reverse("expire_risk_acceptance", args=(1, ra.id)), data)

        ra.refresh_from_db()

        self.assertTrue(all(finding.sla_start_date == timezone.now().date() for finding in findings))

    def test_reinstate_risk_acceptance_findings_accepted(self):
        # first create an expired risk acceptance
        self.test_expire_risk_acceptance_findings_active()
        ra = Risk_Acceptance.objects.last()

        findings = ra.accepted_findings.all()

        data = {"id": ra.id}

        self.client.post(reverse("reinstate_risk_acceptance", args=(1, ra.id)), data)

        ra.refresh_from_db()
        expiration_delta_days = get_system_setting("risk_acceptance_form_default_days", 90)
        risk_acceptance_expiration_date = timezone.now() + relativedelta(days=expiration_delta_days)

        self.assertEqual(ra.expiration_date.date(), risk_acceptance_expiration_date.date())
        self.assertIsNone(ra.expiration_date_handled)
        self.assertIsNone(ra.expiration_date_warned)
        self.assert_all_inactive_risk_accepted(findings)
        self.assert_all_active_not_risk_accepted(Finding.objects.filter(test__engagement=1).filter(~Q(id=2)))
        # findings remain in (expired) risk acceptance
        self.assertTrue(all(finding in ra.accepted_findings.all() for finding in findings))

    def create_multiple_ras(self):
        ra_data = copy.copy(self.data_risk_accceptance)
        ra_data["accepted_findings"] = [2]
        ra_data["return_url"] = reverse("view_finding", args=(2, ))
        self.add_risk_acceptance(1, ra_data, 2)
        ra1 = Risk_Acceptance.objects.last()

        ra_data = copy.copy(self.data_risk_accceptance)
        ra_data["accepted_findings"] = [7]
        ra_data["return_url"] = reverse("view_finding", args=(7, ))
        self.add_risk_acceptance(1, ra_data, 7)
        ra2 = Risk_Acceptance.objects.last()

        ra_data = copy.copy(self.data_risk_accceptance)
        ra_data["accepted_findings"] = [22]
        ra_data["return_url"] = reverse("view_finding", args=(22, ))
        self.add_risk_acceptance(3, ra_data, 22)
        ra3 = Risk_Acceptance.objects.last()

        return ra1, ra2, ra3

    def test_expiration_handler(self):
        ra1, ra2, ra3 = self.create_multiple_ras()
        system_settings = System_Settings.objects.get(no_cache=True)
        system_settings.risk_acceptance_notify_before_expiration = 10
        system_settings.save()
        heads_up_days = system_settings.risk_acceptance_notify_before_expiration

        # ra1: expire in 9 days -> warn:yes, expire:no
        # ra2: expire in 11 days -> warn:no, expire:no
        # ra3: expire 5 days ago -> warn:no, expire:yes (expiration not handled yet, so expire)
        ra1.expiration_date = datetime.datetime.now(datetime.UTC) + relativedelta(days=heads_up_days - 1)
        ra2.expiration_date = datetime.datetime.now(datetime.UTC) + relativedelta(days=heads_up_days + 1)
        ra3.expiration_date = datetime.datetime.now(datetime.UTC) - relativedelta(days=5)
        ra1.save()
        ra2.save()
        ra3.save()

        to_warn = ra_helper.get_almost_expired_risk_acceptances_to_handle(heads_up_days=heads_up_days)
        to_expire = ra_helper.get_expired_risk_acceptances_to_handle()

        self.assertIn(ra1, to_warn)
        self.assertNotIn(ra2, to_warn)
        self.assertNotIn(ra3, to_warn)

        self.assertNotIn(ra1, to_expire)
        self.assertNotIn(ra2, to_expire)
        self.assertIn(ra3, to_expire)

        # run job
        ra_helper.expiration_handler()

        ra1.refresh_from_db()
        ra2.refresh_from_db()
        ra3.refresh_from_db()

        self.assertIsNotNone(ra1.expiration_date_warned)
        self.assertIsNone(ra2.expiration_date_warned)
        self.assertIsNone(ra3.expiration_date_warned)

        self.assertIsNone(ra1.expiration_date_handled)
        self.assertIsNone(ra2.expiration_date_handled)
        self.assertIsNotNone(ra3.expiration_date_handled)

        to_warn = ra_helper.get_almost_expired_risk_acceptances_to_handle(heads_up_days=heads_up_days)
        to_expire = ra_helper.get_expired_risk_acceptances_to_handle()

        # after handling no ra should be select for anything
        self.assertFalse(any(ra in to_warn for ra in [ra1, ra2, ra3]))
        self.assertFalse(any(ra in to_expire for ra in [ra1, ra2, ra3]))

    def detach_from_engagements(self, ra):
        """
        Leave a risk acceptance without an engagement.

        Not corrupt data: `RiskAcceptanceSerializer.create` only attaches an engagement when
        the risk acceptance already has findings, and the Pro plugin tracks the association on
        its own model rather than on `Engagement.risk_acceptance`.
        """
        for engagement in ra.engagement_set.all():
            engagement.risk_acceptance.remove(ra)
        ra.refresh_from_db()
        self.assertIsNone(ra.engagement, msg="setup failed: risk acceptance is still attached to an engagement")

    def notified_risk_acceptances(self, mock_create_notification):
        return [call.kwargs.get("risk_acceptance") for call in mock_create_notification.call_args_list]

    # Regression: expiration_handler aborted the entire run with
    # "AttributeError: 'NoneType' object has no attribute 'product'" as soon as it reached a
    # risk acceptance not attached to any engagement, so every remaining risk acceptance in the
    # batch was left unhandled and the job failed again on every subsequent run.
    def test_expiration_handler_warns_via_findings_when_engagement_link_is_missing(self):
        ra1, ra2, ra3 = self.create_multiple_ras()
        system_settings = System_Settings.objects.get(no_cache=True)
        system_settings.risk_acceptance_notify_before_expiration = 10
        system_settings.save()
        heads_up_days = system_settings.risk_acceptance_notify_before_expiration

        # both are inside the heads-up window, ra1 (created first, so handled first) has no engagement
        ra1.expiration_date = datetime.datetime.now(datetime.UTC) + relativedelta(days=heads_up_days - 1)
        ra2.expiration_date = datetime.datetime.now(datetime.UTC) + relativedelta(days=heads_up_days - 1)
        ra3.expiration_date = datetime.datetime.now(datetime.UTC) + relativedelta(days=heads_up_days + 1)
        ra1.save()
        ra2.save()
        ra3.save()
        expected_engagement = ra1.accepted_findings.first().test.engagement
        self.detach_from_engagements(ra1)

        with patch("dojo.risk_acceptance.helper.create_notification") as mock_create_notification:
            ra_helper.expiration_handler()

        ra1.refresh_from_db()
        ra2.refresh_from_db()

        # the missing link is recovered from the accepted findings rather than dropping the notification
        notified = self.notified_risk_acceptances(mock_create_notification)
        self.assertIn(ra1, notified, msg=f"risk acceptance with findings but no engagement was not notified about, got {notified}")
        self.assertIn(ra2, notified, msg=f"expected a notification for the attached risk acceptance, got {notified}")

        ra1_call = next(c for c in mock_create_notification.call_args_list if c.kwargs.get("risk_acceptance") == ra1)
        self.assertEqual(
            ra1_call.kwargs.get("engagement"), expected_engagement,
            msg=f"expected engagement={expected_engagement}, notified with {ra1_call.kwargs.get('engagement')}",
        )
        self.assertEqual(
            ra1_call.kwargs.get("product"), expected_engagement.product,
            msg=f"expected product={expected_engagement.product}, notified with {ra1_call.kwargs.get('product')}",
        )

        self.assertIsNotNone(ra1.expiration_date_warned, msg="risk acceptance with no engagement link was never warned")
        self.assertIsNotNone(ra2.expiration_date_warned, msg="attached risk acceptance was never warned")

    # Regression: the shape produced by the Pro standalone "New Risk Acceptance" page, which
    # pre-fills an expiration date and posts no findings, so the risk acceptance is selected by
    # the heads-up query while having neither an engagement nor anything to derive one from.
    def test_expiration_handler_skips_risk_acceptance_with_no_engagement_and_no_findings(self):
        ra1, ra2, ra3 = self.create_multiple_ras()
        system_settings = System_Settings.objects.get(no_cache=True)
        system_settings.risk_acceptance_notify_before_expiration = 10
        system_settings.save()
        heads_up_days = system_settings.risk_acceptance_notify_before_expiration

        for ra in (ra1, ra2, ra3):
            ra.expiration_date = datetime.datetime.now(datetime.UTC) + relativedelta(days=heads_up_days + 1)
            ra.save()

        empty_ra = Risk_Acceptance.objects.create(
            name="Accept: no findings, no engagement",
            owner=self.get_test_admin(),
            expiration_date=datetime.datetime.now(datetime.UTC) + relativedelta(days=heads_up_days - 1),
        )
        attached_ra = ra1
        attached_ra.expiration_date = datetime.datetime.now(datetime.UTC) + relativedelta(days=heads_up_days - 1)
        attached_ra.save()
        self.assertIsNone(empty_ra.engagement, msg="setup failed: expected no engagement")
        self.assertFalse(empty_ra.accepted_findings.exists(), msg="setup failed: expected no accepted findings")
        self.assertIn(
            empty_ra, ra_helper.get_almost_expired_risk_acceptances_to_handle(heads_up_days=heads_up_days),
            msg="setup failed: the empty risk acceptance is not selected by the heads-up query",
        )

        with patch("dojo.risk_acceptance.helper.create_notification") as mock_create_notification:
            ra_helper.expiration_handler()

        empty_ra.refresh_from_db()
        attached_ra.refresh_from_db()

        # nothing to name a product with, so no notification - but the job must not die over it
        notified = self.notified_risk_acceptances(mock_create_notification)
        self.assertNotIn(empty_ra, notified, msg="a risk acceptance with no findings has no product to notify about")
        self.assertIn(attached_ra, notified, msg=f"the rest of the batch was abandoned, notified: {notified}")

        self.assertIsNotNone(
            empty_ra.expiration_date_warned,
            msg="empty risk acceptance stays unwarned and is re-selected, failing the job again on every run",
        )
        self.assertIsNotNone(attached_ra.expiration_date_warned, msg="attached risk acceptance was never warned")

    # Regression: same root cause, on the expiry half of the job.
    def test_expiration_handler_expires_risk_acceptance_without_engagement_link(self):
        ra1, ra2, ra3 = self.create_multiple_ras()
        system_settings = System_Settings.objects.get(no_cache=True)
        system_settings.risk_acceptance_notify_before_expiration = 10
        system_settings.save()
        heads_up_days = system_settings.risk_acceptance_notify_before_expiration

        # ra3 is past its expiration date and has no engagement, ra1 is only due a heads-up
        ra1.expiration_date = datetime.datetime.now(datetime.UTC) + relativedelta(days=heads_up_days - 1)
        ra2.expiration_date = datetime.datetime.now(datetime.UTC) + relativedelta(days=heads_up_days + 1)
        ra3.expiration_date = datetime.datetime.now(datetime.UTC) - relativedelta(days=5)
        ra1.save()
        ra2.save()
        ra3.save()
        findings = list(ra3.accepted_findings.all())
        expected_engagement = ra3.accepted_findings.first().test.engagement
        self.detach_from_engagements(ra3)

        with patch("dojo.risk_acceptance.helper.create_notification") as mock_create_notification:
            ra_helper.expiration_handler()

        ra1.refresh_from_db()
        ra3.refresh_from_db()

        # the expiry happens and the notification still goes out, addressed via the findings
        self.assertIsNotNone(ra3.expiration_date_handled, msg="risk acceptance with no engagement link was never expired")
        self.assert_all_active_not_risk_accepted(findings)

        notified = self.notified_risk_acceptances(mock_create_notification)
        self.assertIn(ra3, notified, msg=f"expired risk acceptance with findings was not notified about, got {notified}")
        ra3_call = next(c for c in mock_create_notification.call_args_list if c.kwargs.get("risk_acceptance") == ra3)
        self.assertEqual(
            ra3_call.kwargs.get("engagement"), expected_engagement,
            msg=f"expected engagement={expected_engagement}, notified with {ra3_call.kwargs.get('engagement')}",
        )

        # the rest of the batch is still processed instead of being abandoned mid-run
        self.assertIsNotNone(ra1.expiration_date_warned, msg="the run stopped at the risk acceptance with no engagement link")
