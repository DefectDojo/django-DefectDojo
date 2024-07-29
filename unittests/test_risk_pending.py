import copy
from django.test import TestCase
from datetime import timedelta
from dateutil.relativedelta import relativedelta
from django.core.management import call_command
from django.utils.datastructures import MultiValueDict
from django.utils import timezone
from django.utils.http import urlencode
from django.urls import reverse
from django.db.models import Q
from dojo.models import (
    Risk_Acceptance,
    Finding,
    Engagement,
    Product,
    Product_Type,
    User)
from dojo.utils import get_system_setting
from .dojo_test_case import DojoTestCase
from dojo.risk_acceptance import queries


class RiskAcceptancePendingTestUI(DojoTestCase):
    fixtures = ['dojo_testdata.json']

    data_risk_accceptance = {
        'name': 'Accept: Unit test',
        'accepted_findings': [72808],
        'recommendation': 'A',
        'accepted_by': ["user1", "user2"],
        'owner': '2',
        'expiration_date': '2021-07-15',
        'notes': '',
        'expiration_date_warned': '2021-07-15',
        'expiration_date_handled': '2021-07-15',
        'decision': 'A'
    }

    data_remove_finding_from_rp = {
        'remove_finding': 'Remove',
        'remove_finding_id': 666,
    }

    def __init__(self, *args, **kwargs):
        DojoTestCase.__init__(self, *args, **kwargs)

    def setUp(self):
        self.system_settings(enable_jira=True)
        self.client.force_login(self.get_test_admin())

    def add_risk_acceptance(self, eid, data_risk_accceptance, fid):
        args = (eid, fid, )
        response = self.client.post(reverse('add_risk_acceptance', args=args), data_risk_accceptance)
        print("debug_respose", response)
        self.assertEqual(302, response.status_code, response.content[:1000])
        return response

    def assert_all_active_not_risk_accepted(self, findings):
        if not all(finding.active for finding in findings):
            return False

        if not any(finding.risk_accepted for finding in findings):
            return True

        return False

    def assert_all_inactive_risk_accepted(self, findings):
        if any(finding.active for finding in findings):
            return False

        if all(finding.risk_accepted for finding in findings):
            return True

        return False

    def test_add_risk_acceptance_single_findings_accepted(self):
        ra_data = copy.copy(self.data_risk_accceptance)
        ra_data['accepted_findings'] = [2]
        ra_data['return_url'] = reverse('view_finding', args=(2, ))
        response = self.add_risk_acceptance(1, ra_data, 2)
        self.assertEqual('/finding/2', response.url)
        ra = Risk_Acceptance.objects.last()
        self.assert_all_active_not_risk_accepted(ra.accepted_findings.all())

    def test_add_risk_acceptance_multiple_findings_accepted(self):
        ra_data = copy.copy(self.data_risk_accceptance)
        ra_data['accepted_findings'] = [2, 3]
        response = self.add_risk_acceptance(1, ra_data, 2)
        self.assertEqual('/engagement/1', response.url)
        ra = Risk_Acceptance.objects.last()
        self.assert_all_active_not_risk_accepted(ra.accepted_findings.all())

    def test_add_findings_to_risk_acceptance_findings_accepted(self):
        self.test_add_risk_acceptance_multiple_findings_accepted()
        ra = Risk_Acceptance.objects.last()

        data_add_findings_to_ra = {
            'add_findings': 'Add Selected Findings',
            'accepted_findings': [4, 5]
        }
        ra.accepted_by = ["user1", "user2"]
        ra.save()

        response = self.client.post(reverse('view_risk_acceptance', args=(1, ra.id)),
                    urlencode(MultiValueDict(data_add_findings_to_ra), doseq=True),
                    content_type='application/x-www-form-urlencoded')

        self.assertEqual(302, response.status_code, response.content[:1000])
        self.assert_all_inactive_risk_accepted(Finding.objects.filter(id__in=[2, 3, 4, 5]))

    def test_remove_findings_from_risk_acceptance_findings_active(self):
        self.test_add_risk_acceptance_multiple_findings_accepted()

        data = copy.copy(self.data_remove_finding_from_rp)
        data['remove_finding_id'] = 2
        ra = Risk_Acceptance.objects.last()
        response = self.client.post(reverse('view_risk_acceptance', args=(1, ra.id)), data)
        self.assertEqual(302, response.status_code, response.content[:1000])
        self.assert_all_active_not_risk_accepted(Finding.objects.filter(id=2))
        self.assert_all_inactive_risk_accepted(Finding.objects.filter(id=3))

    def test_remove_risk_acceptance_findings_active(self):
        self.test_add_risk_acceptance_multiple_findings_accepted()
        ra = Risk_Acceptance.objects.last()

        findings = ra.accepted_findings.all()

        data = {'id': ra.id}

        self.client.post(reverse('delete_risk_acceptance', args=(1, ra.id, )), data)

        self.assert_all_active_not_risk_accepted(findings)
        self.assert_all_active_not_risk_accepted(Finding.objects.filter(test__engagement=1))

    def test_expire_risk_acceptance_findings_active(self):
        self.test_add_risk_acceptance_multiple_findings_accepted()
        ra = Risk_Acceptance.objects.last()
        findings = ra.accepted_findings.all()
        data = {'id': ra.id}
        self.client.post(reverse('expire_risk_acceptance', args=(1, ra.id, )), data)

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

        data = {'id': ra.id}

        self.client.post(reverse('expire_risk_acceptance', args=(1, ra.id, )), data)

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

        data = {'id': ra.id}

        self.client.post(reverse('expire_risk_acceptance', args=(1, ra.id, )), data)

        ra.refresh_from_db()

        self.assertTrue(all(finding.sla_start_date != timezone.now().date() for finding in findings))


    def test_reinstate_risk_acceptance_findings_accepted(self):
        # first create an expired risk acceptance
        self.test_expire_risk_acceptance_findings_active()
        ra = Risk_Acceptance.objects.last()

        findings = ra.accepted_findings.all()

        data = {'id': ra.id}

        self.client.post(reverse('reinstate_risk_acceptance', args=(1, ra.id, )), data)

        ra.refresh_from_db()
        expiration_delta_days = get_system_setting('risk_acceptance_form_default_days', 90)
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
        ra_data['accepted_findings'] = [2]
        ra_data['return_url'] = reverse('view_finding', args=(2, ))
        self.add_risk_acceptance(1, ra_data, 2)
        ra1 = Risk_Acceptance.objects.last()

        ra_data = copy.copy(self.data_risk_accceptance)
        ra_data['accepted_findings'] = [7]
        ra_data['return_url'] = reverse('view_finding', args=(7, ))
        self.add_risk_acceptance(1, ra_data, 7)
        ra2 = Risk_Acceptance.objects.last()

        ra_data = copy.copy(self.data_risk_accceptance)
        ra_data['accepted_findings'] = [22]
        ra_data['return_url'] = reverse('view_finding', args=(22, ))
        self.add_risk_acceptance(3, ra_data, 22)
        ra3 = Risk_Acceptance.objects.last()

        return ra1, ra2, ra3


class RiskPendingQuerys(TestCase):

    fixtures = ["dojo_testdata.json"]

    def __init__(self, *args, **kwargs):
        DojoTestCase.__init__(self, *args, **kwargs)
    
    def setUp(self):
        self.product_id = 1
        self.ideal_percentage_closed = 0.80
        self.ideal_percentage_accepted = 0.40
        self.days = 90
        self.queryset = Finding.objects.select_related('test__engagement').filter(test__engagement__product=self.product_id)
    
    def test_abuse_control_vulnerability_closed_with_days(self):
        result = queries.abuse_control_min_vulnerability_closed(self.product_id,
                                                                self.ideal_percentage_closed,
                                                                days=self.days)

        self.assertAlmostEqual(round(result['current_percentage'], 2), 1)
        self.assertEqual(result['ideal_percentage'], 0.8)
        self.assertEqual(result['ideal_close_finding'], 1)
        self.assertEqual(result['total_finding'], 1)
        self.assertEqual(result['total_close_finding'], 1)
        self.assertTrue(result['status'])
        self.assertEqual(len(result["message"]), 121)

    def test_abuse_control_vulnerability_closed_without_days(self):
        result = queries.abuse_control_min_vulnerability_closed(self.product_id, self.ideal_percentage_closed)
        print(result)
        self.assertAlmostEqual(round(result['current_percentage'], 2), 0.29)
        self.assertEqual(result['ideal_percentage'], 0.8)
        self.assertEqual(result['ideal_close_finding'], 6)
        self.assertEqual(result['total_finding'], 7)
        self.assertEqual(result['total_close_finding'], 2)
        self.assertFalse(result['status'])
        self.assertEqual(len(result["message"]), 179)
    
    def test_pass_abuse_control_vulnerability_accepted(self):
        finding = self.queryset[0]
        finding.risk_status = "Risk Accepted"
        finding.active = False
        finding.risk_accepted = True
        finding.save()
        result = queries.abuse_control_max_vulnerability_accepted(self.product_id, self.ideal_percentage_accepted)
        self.assertEqual(result["persentage_finding_accepted"], 0.2)
        self.assertEqual(result["total_finding_accepted"], 1)
        self.assertEqual(result["total_finding_active"], 5)
        self.assertTrue(result["status"])
        self.assertEqual(len(result["message"]), 119)

    def test_not_pass_abuse_control_vulnerability_accepted(self):
        for i in range(0, 3):
            finding = self.queryset[i]
            finding.risk_status = "Risk Accepted"
            finding.active = False
            finding.risk_accepted = True
            finding.save()

        result = queries.abuse_control_max_vulnerability_accepted(self.product_id, self.ideal_percentage_accepted)
        self.assertEqual(result["total_finding_active"], 5)
        self.assertEqual(result["total_finding_accepted"], 3)
        self.assertEqual(result["persentage_finding_accepted"], 0.6)
        self.assertFalse(result["status"])
        self.assertEqual(len(result["message"]), 172)

    def test_pass_control_abuseo_vulnerability_accepted_is_mitigated(self):
        finding = self.queryset[0]
        finding.risk_status = "Risk Accepted"
        finding.active = False
        finding.risk_accepted = True
        finding.mitigated = "2020-05-01"
        finding.save()
        result = queries.abuse_control_max_vulnerability_accepted(self.product_id, self.ideal_percentage_accepted)
        self.assertEqual(result["persentage_finding_accepted"], 0.0)
        self.assertEqual(result["total_finding_accepted"], 0)
        self.assertEqual(result["total_finding_active"], 4)
        self.assertTrue(result["status"])
        self.assertEqual(len(result["message"]), 118)
