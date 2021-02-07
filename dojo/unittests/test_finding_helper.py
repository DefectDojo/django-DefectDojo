from django.test import TestCase, override_settings
from dojo.models import Finding
from dojo.finding import helper
from django.contrib.auth.models import User
from unittest import mock
import datetime

frozen_datetime = datetime.datetime(2021, 1, 1, 2, 2, 2)


@override_settings(USE_TZ=False)
class TestUpdateFindingStatus(TestCase):
    def setUp(self):
        self.user_1 = User()
        self.user_2 = User()

    def get_mitigation_status_fields(self, finding):
        return finding.is_Mitigated, finding.mitigated, finding.mitigated_by

    def test_default_state(self):
        self.assertEqual(
            self.get_mitigation_status_fields(Finding()),
            (False, None, None)
        )

    @mock.patch('dojo.finding.helper.datetime')
    def test_mark_fresh_as_mitigated(self, mock_dt):
        mock_dt.now.return_value = frozen_datetime
        finding = Finding(is_Mitigated=True, active=False)
        changed = helper.update_finding_status(finding, self.user_1)
        self.assertEqual(
            self.get_mitigation_status_fields(finding),
            (True, frozen_datetime, self.user_1)
        )
        self.assertTrue(changed)

    @mock.patch('dojo.finding.helper.datetime')
    @mock.patch('dojo.finding.helper.timezone')
    @mock.patch('dojo.finding.helper.can_edit_mitigated_data', return_value=False)
    def test_mark_old_active_as_mitigated(self, mock_can_edit, mock_tz, mock_dt):
        mock_dt.now.return_value = frozen_datetime
        mock_tz.now.return_value = frozen_datetime

        old_finding = Finding()
        new_finding = Finding(is_Mitigated=True, active=False)
        changed = helper.update_finding_status(new_finding, self.user_1, old_finding)
        self.assertEqual(
            self.get_mitigation_status_fields(new_finding),
            (True, frozen_datetime, self.user_1)
        )
        self.assertFalse(changed)

    @mock.patch('dojo.finding.helper.datetime')
    @mock.patch('dojo.finding.helper.timezone')
    @mock.patch('dojo.finding.helper.can_edit_mitigated_data', return_value=True)
    def test_mark_old_active_as_mitigated_custom_edit(self, mock_can_edit, mock_tz, mock_dt):
        mock_dt.now.return_value = frozen_datetime
        mock_tz.now.return_value = frozen_datetime

        custom_mitigated = datetime.datetime.now()

        old_finding = Finding()
        new_finding = Finding(is_Mitigated=True, active=False, mitigated=custom_mitigated, mitigated_by=self.user_2)
        changed = helper.update_finding_status(new_finding, self.user_1, old_finding)
        self.assertEqual(
            self.get_mitigation_status_fields(new_finding),
            (True, custom_mitigated, self.user_2)
        )
        self.assertFalse(changed)

    @mock.patch('dojo.finding.helper.datetime')
    @mock.patch('dojo.finding.helper.timezone')
    @mock.patch('dojo.finding.helper.can_edit_mitigated_data', return_value=True)
    def test_update_old_mitigated_with_custom_edit(self, mock_can_edit, mock_tz, mock_dt):
        mock_dt.now.return_value = frozen_datetime
        mock_tz.now.return_value = frozen_datetime

        custom_mitigated = datetime.datetime.now()

        old_finding = Finding(is_Mitigated=True, active=False, mitigated=frozen_datetime, mitigated_by=self.user_1)
        new_finding = Finding(is_Mitigated=True, active=False, mitigated=custom_mitigated, mitigated_by=self.user_2)
        changed = helper.update_finding_status(new_finding, self.user_1, old_finding)
        # nothing actually is changed
        self.assertEqual(
            self.get_mitigation_status_fields(new_finding),
            (True, custom_mitigated, self.user_2)
        )
        self.assertFalse(changed)

    @mock.patch('dojo.finding.helper.datetime')
    @mock.patch('dojo.finding.helper.timezone')
    @mock.patch('dojo.finding.helper.can_edit_mitigated_data', return_value=False)
    def test_update_old_mitigated_with_missing_data(self, mock_can_edit, mock_tz, mock_dt):
        mock_dt.now.return_value = frozen_datetime
        mock_tz.now.return_value = frozen_datetime

        custom_mitigated = datetime.datetime.now()

        old_finding = Finding(is_Mitigated=True, active=False, mitigated=custom_mitigated, mitigated_by=self.user_2)
        new_finding = Finding(is_Mitigated=True, active=False)
        changed = helper.update_finding_status(new_finding, self.user_1, old_finding)
        # mitigated and mitigated_vy get updated
        self.assertEqual(
            self.get_mitigation_status_fields(new_finding),
            (True, frozen_datetime, self.user_1)
        )
        self.assertTrue(changed)

    @mock.patch('dojo.finding.helper.datetime')
    @mock.patch('dojo.finding.helper.timezone')
    @mock.patch('dojo.finding.helper.can_edit_mitigated_data', return_value=False)
    def test_set_old_mitigated_as_active(self, mock_can_edit, mock_tz, mock_dt):
        mock_dt.now.return_value = frozen_datetime
        mock_tz.now.return_value = frozen_datetime

        old_finding = Finding(is_Mitigated=True, active=False, mitigated=frozen_datetime, mitigated_by=self.user_2)
        new_finding = Finding(active=True)
        changed = helper.update_finding_status(new_finding, self.user_1, old_finding)
        self.assertEqual(
            self.get_mitigation_status_fields(new_finding),
            (False, None, None)
        )
        self.assertFalse(changed)
