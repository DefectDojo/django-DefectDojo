from .dojo_test_case import DojoTestCase
from dojo.models import Finding, Test, Vulnerability_Id, Finding_Template, Vulnerability_Id_Template
from django.contrib.auth.models import User
from unittest import mock
from unittest.mock import patch
from crum import impersonate
import datetime
from django.utils import timezone
import logging
from dojo.finding.helper import save_vulnerability_ids, save_vulnerability_ids_template

logger = logging.getLogger(__name__)


# frozen_datetime = timezone.make_aware(datetime.datetime(2021, 1, 1, 2, 2, 2), timezone.get_default_timezone())
frozen_datetime = timezone.now()


class TestUpdateFindingStatusSignal(DojoTestCase):
    fixtures = ['dojo_testdata.json']

    def setUp(self):
        self.user_1 = User.objects.get(id='1')
        self.user_2 = User.objects.get(id='2')

    def get_status_fields(self, finding):
        logger.debug('%s, %s, %s, %s, %s, %s, %s, %s', finding.active, finding.verified, finding.false_p, finding.out_of_scope, finding.is_mitigated, finding.mitigated, finding.mitigated_by, finding.last_status_update)
        return finding.active, finding.verified, finding.false_p, finding.out_of_scope, finding.is_mitigated, finding.mitigated, finding.mitigated_by, finding.last_status_update

    @mock.patch('dojo.finding.helper.timezone.now')
    def test_new_finding(self, mock_tz):
        mock_tz.return_value = frozen_datetime
        with impersonate(self.user_1):
            test = Test.objects.last()
            finding = Finding(test=test)
            finding.save()

            self.assertEqual(
                self.get_status_fields(finding),
                (True, True, False, False, False, None, None, frozen_datetime)
            )

    @mock.patch('dojo.finding.helper.timezone.now')
    def test_no_status_change(self, mock_tz):
        mock_tz.return_value = frozen_datetime
        with impersonate(self.user_1):
            test = Test.objects.last()
            finding = Finding(test=test)
            finding.save()

            status_fields = self.get_status_fields(finding)

            finding.title = finding.title + '!!!'
            finding.save()

            self.assertEqual(
                self.get_status_fields(finding),
                status_fields
            )

    @mock.patch('dojo.finding.helper.timezone.now')
    def test_mark_fresh_as_mitigated(self, mock_dt):
        mock_dt.return_value = frozen_datetime
        with impersonate(self.user_1):
            test = Test.objects.last()
            finding = Finding(test=test, is_mitigated=True, active=False)
            finding.save()
            self.assertEqual(
                self.get_status_fields(finding),
                (False, True, False, False, True, frozen_datetime, self.user_1, frozen_datetime)
            )

    @mock.patch('dojo.finding.helper.timezone.now')
    @mock.patch('dojo.finding.helper.can_edit_mitigated_data', return_value=False)
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
                (False, True, False, False, True, frozen_datetime, self.user_1, frozen_datetime)
            )

    @mock.patch('dojo.finding.helper.timezone.now')
    @mock.patch('dojo.finding.helper.can_edit_mitigated_data', return_value=True)
    def test_mark_old_active_as_mitigated_custom_edit(self, mock_can_edit, mock_tz):
        mock_tz.return_value = frozen_datetime

        custom_mitigated = datetime.datetime.now()

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
                (False, True, False, False, True, custom_mitigated, self.user_2, frozen_datetime)
            )

    @mock.patch('dojo.finding.helper.timezone.now')
    @mock.patch('dojo.finding.helper.can_edit_mitigated_data', return_value=True)
    def test_update_old_mitigated_with_custom_edit(self, mock_can_edit, mock_tz):
        mock_tz.return_value = frozen_datetime

        custom_mitigated = datetime.datetime.now()

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
                (False, True, False, False, True, custom_mitigated, self.user_2, frozen_datetime)
            )

    @mock.patch('dojo.finding.helper.timezone.now')
    @mock.patch('dojo.finding.helper.can_edit_mitigated_data', return_value=True)
    def test_update_old_mitigated_with_missing_data(self, mock_can_edit, mock_tz):
        mock_tz.return_value = frozen_datetime

        custom_mitigated = datetime.datetime.now()

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
                (False, True, False, False, True, frozen_datetime, self.user_1, frozen_datetime)
            )

    @mock.patch('dojo.finding.helper.timezone.now')
    @mock.patch('dojo.finding.helper.can_edit_mitigated_data', return_value=True)
    def test_set_old_mitigated_as_active(self, mock_can_edit, mock_tz):
        mock_tz.return_value = frozen_datetime

        with impersonate(self.user_1):
            test = Test.objects.last()
            finding = Finding(test=test, is_mitigated=True, active=False, mitigated=frozen_datetime, mitigated_by=self.user_2)
            logger.debug('save1')
            finding.save()
            finding.active = True
            logger.debug('save2')
            finding.save()

            self.assertEqual(
                self.get_status_fields(finding),
                (True, True, False, False, False, None, None, frozen_datetime)
            )

    @mock.patch('dojo.finding.helper.timezone.now')
    @mock.patch('dojo.finding.helper.can_edit_mitigated_data', return_value=False)
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
                # TODO marking as false positive resets verified to False, possible bug / undesired behaviour?
                (False, False, True, False, True, frozen_datetime, self.user_1, frozen_datetime)
            )


class TestSaveVulnerabilityIds(DojoTestCase):

    @patch('dojo.finding.helper.Vulnerability_Id.objects.filter')
    @patch('django.db.models.query.QuerySet.delete')
    @patch('dojo.finding.helper.Vulnerability_Id.save')
    def test_save_vulnerability_ids(self, save_mock, delete_mock, filter_mock):
        finding = Finding()
        new_vulnerability_ids = ['REF-1', 'REF-2', 'REF-2']
        filter_mock.return_value = Vulnerability_Id.objects.none()

        save_vulnerability_ids(finding, new_vulnerability_ids)

        filter_mock.assert_called_with(finding=finding)
        delete_mock.assert_called_once()
        self.assertEqual(save_mock.call_count, 2)
        self.assertEqual('REF-1', finding.cve)

    @patch('dojo.finding.helper.Vulnerability_Id_Template.objects.filter')
    @patch('django.db.models.query.QuerySet.delete')
    @patch('dojo.finding.helper.Vulnerability_Id_Template.save')
    def test_save_vulnerability_id_templates(self, save_mock, delete_mock, filter_mock):
        finding_template = Finding_Template()
        new_vulnerability_ids = ['REF-1', 'REF-2', 'REF-2']
        filter_mock.return_value = Vulnerability_Id_Template.objects.none()

        save_vulnerability_ids_template(finding_template, new_vulnerability_ids)

        filter_mock.assert_called_with(finding_template=finding_template)
        delete_mock.assert_called_once()
        self.assertEqual(save_mock.call_count, 2)
        self.assertEqual('REF-1', finding_template.cve)
