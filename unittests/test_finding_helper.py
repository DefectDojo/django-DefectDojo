import datetime
import logging
from unittest import mock
from unittest.mock import patch, MagicMock

from crum import impersonate
from django.contrib.auth.models import User
from django.utils import timezone

from dojo.finding.helper import (
    save_vulnerability_ids,
    save_vulnerability_ids_template,
    rule_tags_enable_ia_recommendation,
    rule_repository_enable_ia_recommendation,
    rule_cve_enable_ia_recommendation,
    rule_product_type_or_product_enable_ia_recommendation,
    enable_flow_ia_recommendation,

    )

from dojo.models import (
    Finding,
    Finding_Template,
    Test,
    Vulnerability_Id,
    Vulnerability_Id_Template,
    GeneralSettings)


from .dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)


# frozen_datetime = timezone.make_aware(datetime.datetime(2021, 1, 1, 2, 2, 2), timezone.get_default_timezone())
frozen_datetime = timezone.now()


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

            finding.title = finding.title + "!!!"
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

    @patch("dojo.finding.helper.Vulnerability_Id_Template.objects.filter")
    @patch("django.db.models.query.QuerySet.delete")
    @patch("dojo.finding.helper.Vulnerability_Id_Template.save")
    def test_save_vulnerability_id_templates(self, save_mock, delete_mock, filter_mock):
        finding_template = Finding_Template()
        new_vulnerability_ids = ["REF-1", "REF-2", "REF-2"]
        filter_mock.return_value = Vulnerability_Id_Template.objects.none()

        save_vulnerability_ids_template(finding_template, new_vulnerability_ids)

        filter_mock.assert_called_with(finding_template=finding_template)
        delete_mock.assert_called_once()
        self.assertEqual(save_mock.call_count, 2)
        self.assertEqual("REF-1", finding_template.cve)


    @patch("dojo.finding.helper.GeneralSettings.get_value")
    def test_rule_tags_enable_ia_recommendation(self, mock_get_value):

        # Return GeneralSettings Value
        mock_get_value.return_value = ["tag1", "tag2"]

        mock_tags = MagicMock()
        mock_tags.all.return_value.values_list.return_value = ["tag1", "tag3"]

        mock_finding = MagicMock()
        mock_finding.tags = mock_tags

        # Test case where a tag matches
        result = rule_tags_enable_ia_recommendation(finding=mock_finding)
        assert result is True

        # Test case where no tags match
        mock_tags.all.return_value.values_list.return_value = ["tag3"]
        result = rule_tags_enable_ia_recommendation(finding=mock_finding)
        assert result is False

    @patch("dojo.finding.helper.GeneralSettings.get_value")
    def test_rule_repository_enable_ia_recommendation(self, mock_get_value):
        # Mock data
        mock_finding = MagicMock()
        mock_finding.test.engagement.source_code_management_server.name = "repo1"

        # Return GeneralSettings Value
        mock_get_value.return_value = ["repo1"]

        # Test
        result = rule_repository_enable_ia_recommendation(finding=mock_finding)
        self.assertTrue(result)

        # Negative case
        mock_get_value.return_value = ["repo2"]
        result = rule_repository_enable_ia_recommendation(finding=mock_finding)
        self.assertFalse(result)

    @patch("dojo.finding.helper.GeneralSettings.get_value")
    def test_rule_cve_enable_ia_recommendation(self, mock_get_value):
        # Mock data
        mock_finding = MagicMock()
        mock_finding.cve = "CVE-1234"
        mock_finding.vuln_id_from_tool = None

        # Return GeneralSettings Value
        mock_get_value.return_value = "CVE-\\d+"

        # Test
        result = rule_cve_enable_ia_recommendation(finding=mock_finding)
        self.assertTrue(result)

        # Negative case
        mock_finding.cve = "CVE-A234"
        result = rule_cve_enable_ia_recommendation(finding=mock_finding)
        self.assertFalse(result)

    @patch("dojo.finding.helper.GeneralSettings.get_value")
    @patch("dojo.finding.helper.get_product")
    def test_rule_product_type_or_product_enable_ia_recommendation(
            self,
            mock_get_product,
            mock_get_value):

        mock_finding = MagicMock()
        mock_product = MagicMock()

        mock_product.name = "Product1"
        mock_product.prod_type.name = "Product Type1"

        mock_get_product.return_value = mock_product

        # Return GeneralSettings Value
        mock_get_value.return_value = ["Product Type1"]

        # Test enabled product_type
        result = rule_product_type_or_product_enable_ia_recommendation(finding=mock_finding)
        self.assertTrue(result)

        # Negative case: product type excluded
        mock_product.prod_type.name = "Product Type2"
        mock_get_value.return_value = ["Product Type1"]
        result = rule_product_type_or_product_enable_ia_recommendation(finding=mock_finding)
        self.assertFalse(result)
