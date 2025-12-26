import copy
from unittest.mock import patch
from django.test import TestCase
from datetime import timedelta
from dateutil.relativedelta import relativedelta
from django.core.management import call_command
from django.utils.datastructures import MultiValueDict
from django.utils import timezone
from django.utils.http import urlencode
from django.urls import reverse
from django.db.models import Q
from dojo.api_v2.api_error import ApiError
from dojo.models import (
    Risk_Acceptance,
    Finding,
    Engagement,
    Product,
    Product_Type,
    User)
from dojo.utils import get_system_setting
from .dojo_test_case import DojoTestCase
from dojo.risk_acceptance import helper as ra_helper
from dojo.user.queries import get_role_members, get_user
from dojo.risk_acceptance import queries, risk_pending


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


class SearchFindingCorrelatedTests(TestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.user, _ = User.objects.get_or_create(username="admin")
        self.risk_acceptance = Risk_Acceptance.objects.all().first()
        self.engagement = self.risk_acceptance.engagement
        self.test = self.engagement.test_set.first()
        self.finding1 = Finding.objects.create(test=self.test, reporter=self.user)
        self.risk_acceptance.accepted_findings.add(self.finding1)

    @patch('dojo.risk_acceptance.risk_pending.GeneralSettings.get_value')
    def test_correlated_findings_not_cve(self, mock_get_value):
        mock_get_value.return_value = ["test_tag"]
        self.finding1.cve = ""
        self.finding1.vuln_id_from_tool = ""
        self.finding1.tags.add("test_tag")
        self.finding1.save()
        entry_findings = [self.finding1]
        queryset = risk_pending.search_finding_correlated(
            entry_findings, self.engagement)
        self.assertQuerySetEqual(Risk_Acceptance.objects.none(), queryset)


    @patch('dojo.risk_acceptance.risk_pending.GeneralSettings.get_value')
    def test_correlated_finding_success(self, mock_get_value):
        """finding1 added in risk-acceptance"""
        mock_get_value.return_value = ["test_tag"]
        self.finding1.cve = "CVE-2025-4802"
        self.finding1.vuln_id_from_tool = "CVE-2025-4802"
        self.finding1.save()
        """ceate new finding2 not in risk-acceptance"""
        self.finding2 = Finding.objects.create(test=self.test, reporter=self.user)
        self.finding2.cve = "CVE-2025-4802"
        self.finding2.vuln_id_from_tool = "CVE-2025-4802"
        self.finding2.tags.add("test_tag")
        self.finding2.save()
        entry_findings = [self.finding2]
        queryset = risk_pending.search_finding_correlated(
            entry_findings, self.engagement)
        risk_acceptance_queryset = queryset.filter(id=self.risk_acceptance.id, accepted_findings__cve="CVE-2025-4802")
        findings = risk_acceptance_queryset.first().accepted_findings.all()
        self.assertIn(self.finding2.cve, [finding.cve for finding in findings])

    def test_empty_entry_findings(self):
        entry_findings = []
        queryset = risk_pending.search_finding_correlated(
            entry_findings, self.engagement)
        self.assertQuerySetEqual(Risk_Acceptance.objects.none(), queryset)

    @patch('dojo.risk_acceptance.helper.add_findings_to_risk_acceptance')
    @patch('dojo.user.queries.get_user')
    @patch('dojo.risk_acceptance.risk_pending.GeneralSettings.get_value')
    def test_add_finding_correlated_success(
            self,
            mock_get_value,
            get_user_mock,
            add_finding_to_risk_acceptance_mock
        ):
        mock_get_value.return_value = ["test_tag"]
        self.user.username = "admin"
        self.user.save()
        get_user_mock.return_value = self.user
        add_finding_to_risk_acceptance_mock.return_value = True
        """Test successful addition of correlated findings"""
        self.finding2 = Finding.objects.create(
            test=self.test, reporter=self.user, severity="High"
        )
        self.finding2.cve = "CVE-2025-4802"
        self.finding2.vuln_id_from_tool = "CVE-2025-4802"
        self.finding2.tags.add("test_tag")
        self.finding2.save()

        self.risk_acceptance.accepted_findings.add(self.finding2)
        self.risk_acceptance.save()
        queryset = Risk_Acceptance.objects.filter(id=self.risk_acceptance.id)
        entry_findings = [self.finding2]
        correlated_ids = risk_pending.add_finding_correlated(entry_findings, queryset)

        self.assertIn(self.finding2.id, correlated_ids)


class GetAttrValuesTests(TestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.finding = Finding.objects.all()

    def test_get_attr_values_single_field(self):
        """Test extracting a single field from objects"""
        objs = [self.finding[0], self.finding[1]]
        fields = ["severity"]
        result = risk_pending.get_attr_values(objs, fields)
        self.assertEqual(result["severity"], ["High", "Low"])

    def test_get_attr_values_multiple_fields(self):
        """Test extracting multiple fields from objects"""
        objs = [self.finding[0], self.finding[1]]
        fields = ["severity", "cve", "vuln_id_from_tool"]
        result = risk_pending.get_attr_values(objs, fields)
        self.assertEqual(result["severity"], ["High", "Low"])
        self.assertEqual(result["cve"], [None, None])
        self.assertEqual(result["vuln_id_from_tool"], [None, None])

    def test_get_attr_values_empty_objects(self):
        """Test with an empty list of objects"""
        objs = []
        fields = ["severity", "cve"]
        result = risk_pending.get_attr_values(objs, fields)
        self.assertEqual(result["severity"], [])
        self.assertEqual(result["cve"], [])

    def test_get_attr_values_field_not_present(self):
        """Test when a field is not present in the objects"""
        objs = [self.finding[0], self.finding[1]]
        fields = ["non_existent_field"]
        result = risk_pending.get_attr_values(objs, fields)
        self.assertEqual(result["non_existent_field"], [])
