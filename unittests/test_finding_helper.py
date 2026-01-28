import datetime
import logging
from unittest import mock
from unittest.mock import patch

from crum import impersonate
from django.contrib.auth.models import User
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.finding.helper import save_vulnerability_ids, save_vulnerability_ids_template
from dojo.models import Finding, Finding_Template, Test, Vulnerability_Id
from unittests.dojo_test_case import DojoAPITestCase, DojoTestCase, versioned_fixtures

logger = logging.getLogger(__name__)


# frozen_datetime = timezone.make_aware(datetime.datetime(2021, 1, 1, 2, 2, 2), timezone.get_default_timezone())
frozen_datetime = timezone.now()


@versioned_fixtures
class TestUpdateFindingStatusSignal(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.user_1 = User.objects.get(id="1")
        self.user_2 = User.objects.get(id="2")

    def get_status_fields(self, finding):
        logger.debug("%s, %s, %s, %s, %s, %s, %s, %s", finding.active, finding.verified, finding.false_p, finding.out_of_scope, finding.is_mitigated, finding.mitigated, finding.mitigated_by, finding.last_status_update)
        return finding.active, finding.verified, finding.false_p, finding.out_of_scope, finding.is_mitigated, finding.mitigated, finding.mitigated_by, finding.last_status_update

    @mock.patch("dojo.finding.helper.timezone.now")
    def test_new_finding(self, mock_tz):
        mock_tz.return_value = frozen_datetime
        with impersonate(self.user_1):
            test = Test.objects.last()
            finding = Finding(test=test)
            finding.save()

            self.assertEqual(
                self.get_status_fields(finding),
                (True, False, False, False, False, None, None, frozen_datetime),
            )

    @mock.patch("dojo.finding.helper.timezone.now")
    def test_no_status_change(self, mock_tz):
        mock_tz.return_value = frozen_datetime
        with impersonate(self.user_1):
            test = Test.objects.last()
            finding = Finding(test=test)
            finding.save()

            status_fields = self.get_status_fields(finding)

            finding.title += "!!!"
            finding.save()

            self.assertEqual(
                self.get_status_fields(finding),
                status_fields,
            )

    @mock.patch("dojo.finding.helper.timezone.now")
    def test_mark_fresh_as_mitigated(self, mock_dt):
        mock_dt.return_value = frozen_datetime
        with impersonate(self.user_1):
            test = Test.objects.last()
            finding = Finding(test=test, is_mitigated=True, active=False)
            finding.save()
            self.assertEqual(
                self.get_status_fields(finding),
                (False, False, False, False, True, frozen_datetime, self.user_1, frozen_datetime),
            )

    @mock.patch("dojo.finding.helper.timezone.now")
    @mock.patch("dojo.finding.helper.can_edit_mitigated_data", return_value=False)
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
                (False, False, False, False, True, frozen_datetime, self.user_1, frozen_datetime),
            )

    @mock.patch("dojo.finding.helper.timezone.now")
    @mock.patch("dojo.finding.helper.can_edit_mitigated_data", return_value=True)
    def test_mark_old_active_as_mitigated_custom_edit(self, mock_can_edit, mock_tz):
        mock_tz.return_value = frozen_datetime

        custom_mitigated = datetime.datetime.now(datetime.UTC)

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
                (False, False, False, False, True, custom_mitigated, self.user_2, frozen_datetime),
            )

    @mock.patch("dojo.finding.helper.timezone.now")
    @mock.patch("dojo.finding.helper.can_edit_mitigated_data", return_value=True)
    def test_update_old_mitigated_with_custom_edit(self, mock_can_edit, mock_tz):
        mock_tz.return_value = frozen_datetime

        custom_mitigated = datetime.datetime.now(datetime.UTC)

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
                (False, False, False, False, True, custom_mitigated, self.user_2, frozen_datetime),
            )

    @mock.patch("dojo.finding.helper.timezone.now")
    @mock.patch("dojo.finding.helper.can_edit_mitigated_data", return_value=True)
    def test_update_old_mitigated_with_missing_data(self, mock_can_edit, mock_tz):
        mock_tz.return_value = frozen_datetime

        custom_mitigated = datetime.datetime.now(datetime.UTC)

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
                (False, False, False, False, True, frozen_datetime, self.user_1, frozen_datetime),
            )

    @mock.patch("dojo.finding.helper.timezone.now")
    @mock.patch("dojo.finding.helper.can_edit_mitigated_data", return_value=True)
    def test_set_old_mitigated_as_active(self, mock_can_edit, mock_tz):
        mock_tz.return_value = frozen_datetime

        with impersonate(self.user_1):
            test = Test.objects.last()
            finding = Finding(test=test, is_mitigated=True, active=False, mitigated=frozen_datetime, mitigated_by=self.user_2)
            logger.debug("save1")
            finding.save()
            finding.active = True
            logger.debug("save2")
            finding.save()

            self.assertEqual(
                self.get_status_fields(finding),
                (True, False, False, False, False, None, None, frozen_datetime),
            )

    @mock.patch("dojo.finding.helper.timezone.now")
    @mock.patch("dojo.finding.helper.can_edit_mitigated_data", return_value=False)
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
                # TODO: marking as false positive resets verified to False, possible bug / undesired behaviour?
                (False, False, True, False, True, frozen_datetime, self.user_1, frozen_datetime),
            )

    @mock.patch("dojo.finding.helper.timezone.now")
    @mock.patch("dojo.finding.helper.can_edit_mitigated_data", return_value=False)
    def test_set_active_as_out_of_scope(self, mock_can_edit, mock_tz):
        mock_tz.return_value = frozen_datetime

        with impersonate(self.user_1):
            test = Test.objects.last()
            finding = Finding(test=test)
            finding.save()
            finding.out_of_scope = True
            finding.save()

            self.assertEqual(
                self.get_status_fields(finding),
                # TODO: marking as false positive resets verified to False, possible bug / undesired behaviour?
                (False, False, False, True, True, frozen_datetime, self.user_1, frozen_datetime),
            )


class TestSaveVulnerabilityIds(DojoTestCase):

    @patch("dojo.finding.helper.Vulnerability_Id.objects.filter")
    @patch("django.db.models.query.QuerySet.delete")
    @patch("dojo.finding.helper.Vulnerability_Id.save")
    def test_save_vulnerability_ids(self, save_mock, delete_mock, filter_mock):
        finding = Finding()
        new_vulnerability_ids = ["REF-1", "REF-2", "REF-2"]
        filter_mock.return_value = Vulnerability_Id.objects.none()

        save_vulnerability_ids(finding, new_vulnerability_ids)

        filter_mock.assert_called_with(finding=finding)
        delete_mock.assert_called_once()
        self.assertEqual(save_mock.call_count, 2)
        self.assertEqual("REF-1", finding.cve)

    @patch("dojo.models.Finding_Template.save")
    def test_save_vulnerability_id_templates(self, save_mock):
        finding_template = Finding_Template()
        new_vulnerability_ids = ["REF-1", "REF-2", "REF-2"]

        save_vulnerability_ids_template(finding_template, new_vulnerability_ids)

        save_mock.assert_called_once()
        self.assertEqual("REF-1\nREF-2", finding_template.vulnerability_ids_text)
        self.assertEqual("REF-1", finding_template.cve)


@versioned_fixtures
class TestFindingVulnerabilityIdsAPI(DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.system_settings(enable_jira=True)
        self.testuser = User.objects.get(username="admin")
        self.testuser.usercontactinfo.block_execution = True
        self.testuser.usercontactinfo.save()
        token = Token.objects.get(user=self.testuser)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        self.client.force_login(self.get_test_admin())

    def test_finding_create_without_cve(self):
        # use existing finding as template for a new finding. this finding has no cve
        finding_details = self.get_finding_api(2)
        del finding_details["id"]
        if "cve" in finding_details:
            del finding_details["cve"]
        new_vulnerability_ids = [
            {"vulnerability_id": "RHSA-12345"},
            {"vulnerability_id": "GHSA-7890"},
        ]
        finding_details["vulnerability_ids"] = new_vulnerability_ids
        response = self.post_new_finding_api(finding_details)
        # assert resopnse data
        self.assertIsNone(response.get("cve"))
        self.assertEqual(new_vulnerability_ids, response.get("vulnerability_ids"))

        # assert GET finding
        finding_id = response.get("id")
        response = self.get_finding_api(finding_id)
        self.assertIsNone(response.get("cve"))
        self.assertEqual(new_vulnerability_ids, response.get("vulnerability_ids"))

    def test_finding_create_with_cve(self):
        # use existing finding as template for a new finding. this finding has no cve
        finding_details = self.get_finding_api(2)
        del finding_details["id"]
        if "cve" in finding_details:
            del finding_details["cve"]
        new_vulnerability_ids = [
            {"vulnerability_id": "CVE-2025-12345"},
            {"vulnerability_id": "RHSA-12345"},
            {"vulnerability_id": "GHSA-7890"},
        ]
        finding_details["vulnerability_ids"] = new_vulnerability_ids
        response = self.post_new_finding_api(finding_details)
        # assert response data
        self.assertEqual(new_vulnerability_ids, response.get("vulnerability_ids"))

        # CVE is not in the response, so get it fromt the database
        self.assertEqual("CVE-2025-12345", Finding.objects.get(id=response.get("id")).cve)

    def test_finding_create_and_update_with_cve(self):
        # use existing finding as template for a new finding. this finding has no cve
        finding_details = self.get_finding_api(2)
        del finding_details["id"]
        if "cve" in finding_details:
            del finding_details["cve"]
        new_vulnerability_ids = [
            {"vulnerability_id": "CVE-2025-12345"},
            {"vulnerability_id": "RHSA-12345"},
            {"vulnerability_id": "GHSA-7890"},
        ]
        finding_details["vulnerability_ids"] = new_vulnerability_ids
        response = self.post_new_finding_api(finding_details)
        finding_id = response.get("id")
        # assert resopnse data
        self.assertEqual(new_vulnerability_ids, response.get("vulnerability_ids"))

        # CVE is not in the response, so get it fromt the database
        self.assertEqual("CVE-2025-12345", Finding.objects.get(id=finding_id).cve)

        # change vulnerability_id and remove cve
        updated_vulnerability_ids = [
            {"vulnerability_id": "RHSA-000000"},
        ]
        response = self.patch_finding_api(finding_id, {"vulnerability_ids": updated_vulnerability_ids})
        # assert resopnse data
        self.assertEqual(updated_vulnerability_ids, response.get("vulnerability_ids"))

        # CVE is not in the response, so get it fromt the database
        # current behaviour is that the cve is taken from the first vulnerability_id...
        self.assertEqual("RHSA-000000", Finding.objects.get(id=finding_id).cve)
