# from unittest import skip
import logging
from unittest.mock import patch

from crum import impersonate
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient
from vcr import VCR

import dojo.risk_acceptance.helper as ra_helper
from dojo.jira_link import helper as jira_helper
from dojo.models import Finding, Finding_Group, JIRA_Instance, JIRA_Project, Risk_Acceptance, Test, User
from unittests.dojo_test_case import (
    DojoVCRAPITestCase,
    get_unit_tests_path,
    get_unit_tests_scans_path,
    toggle_system_setting_boolean,
    versioned_fixtures,
    with_system_setting,
)

logger = logging.getLogger(__name__)


# these tests are using vcrpy to record traffic to and from JIRA: https://vcrpy.readthedocs.io/en/latest/usage.html
# after being recorded, the traffic is used for future runs of the tests
# this allows us to locally develop tests, run them, make them work against a real JIRA instance.
# after that we can commit the tests AND the recordings (cassettes).

# the record_mode is set to 'once' by default. this means it will replay responses from the cassette, if there is a cassette.
# otherwise it will create a new cassette and record responses. on the next run the cassette wil be used.

# if changing tests, you can best remove all cassettes before running the tests.
# or you can temporarily set the record_mode to all the make it always go to the real JIRA and record all the traffic.

# when the tests are finished, you'll have to set the assertCassettePlayed method to make it assert
# that all entries in the cassette have been used by the test.

# if you need some credentials for the Defect Dojo JIRA Cloud instance, contact one of the moderators

# some senstive data is filtered out by the filter_headers config option below
# as well as some custom callback functions to filter out cookies.
# please check the recorded files on sensitive data before committing to git


@versioned_fixtures
class JIRAImportAndPushTestApi(DojoVCRAPITestCase):
    fixtures = ["dojo_testdata.json"]

    def __init__(self, *args, **kwargs):
        # TODO: remove __init__ if it does nothing...
        DojoVCRAPITestCase.__init__(self, *args, **kwargs)

    def assert_cassette_played(self):
        if True:  # set to True when committing. set to False when recording new test cassettes
            self.assertTrue(self.cassette.all_played)

    def _get_vcr(self, **kwargs):
        my_vcr = super()._get_vcr(**kwargs)
        my_vcr.record_mode = "once"
        my_vcr.path_transformer = VCR.ensure_suffix(".yaml")
        my_vcr.filter_headers = ["Authorization", "X-Atlassian-Token"]
        my_vcr.cassette_library_dir = str(get_unit_tests_path() / "vcr" / "jira")
        # filters headers doesn't seem to work for cookies, so use callbacks to filter cookies from being recorded
        my_vcr.before_record_request = self.before_record_request
        my_vcr.before_record_response = self.before_record_response
        return my_vcr

    def setUp(self):
        super().setUp()
        self.system_settings(enable_jira=True)
        self.system_settings(enable_webhooks_notifications=True)
        self.testuser = User.objects.get(username="admin")
        self.testuser.usercontactinfo.block_execution = True
        self.testuser.usercontactinfo.save()
        token = Token.objects.get(user=self.testuser)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        self.zap_sample5_filename = get_unit_tests_scans_path("zap") / "5_zap_sample_one.xml"
        self.npm_groups_sample_filename = get_unit_tests_scans_path("npm_audit") / "many_vuln_with_groups.json"
        self.npm_groups_sample_filename2 = get_unit_tests_scans_path("npm_audit") / "many_vuln_with_groups_different_titles.json"
        self.generic_one_finding_with_component_name = get_unit_tests_scans_path("generic") / "generic_one_finding_with_component_name.json"
        self.generic_two_findings_same_component_name = get_unit_tests_scans_path("generic") / "generic_two_findings_same_component_name.json"
        self.generic_report_with_findings = get_unit_tests_scans_path("generic") / "generic_report1.json"
        self.clair_few_findings = get_unit_tests_scans_path("clair") / "clair_few_vuln.json"
        self.client.force_login(self.get_test_admin())

    def test_import_no_push_to_jira(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

    def test_import_with_push_to_jira_is_false(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=False, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

    def test_import_with_push_to_jira(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_with_groups_push_to_jira(self):
        # 7 findings, 5 unique component_name+component_version
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=True, verified=True)
        test_id = import0["test"]
        # all findings should be in a group, so no JIRA issues for individual findings
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 3)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    @with_system_setting("jira_minimum_severity", "Critical")
    def test_import_with_groups_push_to_jira_minimum_critical(self):
        # No Critical findings in report, so expect no groups to be pushed
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=True, verified=True)
        test_id = import0["test"]
        # all findings should be in a group, so no JIRA issues for individual findings
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    @with_system_setting("jira_minimum_severity", "High")
    def test_import_with_groups_push_to_jira_minimum_high(self):
        # 7 findings, 5 unique component_name+component_version
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=True, verified=True)
        test_id = import0["test"]
        # all findings should be in a group, so no JIRA issues for individual findings
        self.assert_jira_issue_count_in_test(test_id, 0)
        # fresh library has only medium findings, so only 2 instead of 3 groups expected
        self.assert_jira_group_issue_count_in_test(test_id, 2)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_with_push_to_jira_epic_as_issue_type(self):
        jira_instance = JIRA_Instance.objects.get(id=2)
        # we choose issue type Epic and test if it can be created successfully.
        # if yes, it means we have successfully populated the Epic Name custom field which is mandatory in JIRA
        jira_instance.default_issue_type = "Epic"
        jira_instance.save()
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_no_push_to_jira_but_push_all(self):
        self.set_jira_push_all_issues(self.get_engagement(1))
        import0 = self.import_scan_with_params(self.zap_sample5_filename, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_with_groups_no_push_to_jira_but_push_all(self):
        self.set_jira_push_all_issues(self.get_engagement(1))
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 3)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_with_push_to_jira_is_false_but_push_all(self):
        self.set_jira_push_all_issues(self.get_engagement(1))
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=False, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_with_groups_with_push_to_jira_is_false_but_push_all(self):
        self.set_jira_push_all_issues(self.get_engagement(1))
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=False, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 3)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_with_group_by_with_push_all_but_no_groups_created(self):
        self.set_jira_push_all_issues(self.get_engagement(1))
        import0 = self.import_scan_with_params(self.zap_sample5_filename, group_by="component_name+component_version", verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_no_push_to_jira_reimport_no_push_to_jira(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        self.reimport_scan_with_params(test_id, self.zap_sample5_filename, verified=True)
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

    def test_import_no_push_to_jira_reimport_push_to_jira_false(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        self.reimport_scan_with_params(test_id, self.zap_sample5_filename, push_to_jira=False, verified=True)
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

    def test_import_no_push_to_jira_reimport_with_push_to_jira(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        self.reimport_scan_with_params(test_id, self.zap_sample5_filename, push_to_jira=True, verified=True)
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_with_groups_no_push_to_jira_reimport_with_push_to_jira(self):
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        self.reimport_scan_with_params(test_id, self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=True, verified=True)
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 3)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_no_push_to_jira_reimport_no_push_to_jira_but_push_all_issues(self):
        self.set_jira_push_all_issues(self.get_engagement(1))
        import0 = self.import_scan_with_params(self.zap_sample5_filename, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        self.reimport_scan_with_params(test_id, self.zap_sample5_filename, verified=True)
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_with_groups_no_push_to_jira_reimport_no_push_to_jira_but_push_all_issues(self):
        self.set_jira_push_all_issues(self.get_engagement(1))
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 3)

        self.reimport_scan_with_params(test_id, self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", verified=True)
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 3)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_no_push_to_jira_reimport_push_to_jira_is_false_but_push_all_issues(self):
        self.set_jira_push_all_issues(self.get_engagement(1))
        import0 = self.import_scan_with_params(self.zap_sample5_filename, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        self.get_jira_issue_updated_map(test_id)

        self.reimport_scan_with_params(test_id, self.zap_sample5_filename, push_to_jira=False, verified=True)
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # when sending in identical data to JIRA, JIRA does NOT update the updated timestamp....
        # self.assert_jira_updated_map_changed(test_id, updated_map)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_with_groups_no_push_to_jira_reimport_push_to_jira_is_false_but_push_all_issues(self):
        self.set_jira_push_all_issues(self.get_engagement(1))
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 3)
        updated_map = self.get_jira_issue_updated_map(test_id)

        self.reimport_scan_with_params(test_id, self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=False, verified=True)
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 3)
        # when sending in identical data to JIRA, JIRA does NOT update the updated timestamp....
        # self.assert_jira_updated_map_changed(test_id, updated_map)
        self.assert_jira_updated_map_unchanged(test_id, updated_map)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_push_to_jira_reimport_with_push_to_jira(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # Get one of the findings from the test
        finding_id = Finding.objects.filter(test__id=test_id).first().id
        self.get_jira_issue_updated(finding_id)
        # re-import and see status change
        self.reimport_scan_with_params(test_id, self.zap_sample5_filename, push_to_jira=True, verified=True)
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        self.get_jira_issue_updated(finding_id)
        # when sending in identical data to JIRA, JIRA does NOT update the updated timestamp....
        # self.assert_jira_updated_change(pre_jira_status, post_jira_status)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_import_twice_push_to_jira(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        import1 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, verified=True)
        test_id1 = import1["test"]
        # duplicates shouldn't be sent to JIRA
        self.assert_jira_issue_count_in_test(test_id1, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

    def add_risk_acceptance(self, eid, data_risk_accceptance, fid=None):
        args = (eid, fid) if fid else (eid,)
        response = self.client.post(reverse("add_risk_acceptance", args=args), data_risk_accceptance)
        self.assertEqual(302, response.status_code, response.content[:1000])
        return response

    def test_import_grouped_reopen_expired_risk_acceptance(self):
        # steps
        # import scan, make sure they are in grouped JIRA
        # risk acceptance all the grouped findings, make sure they are closed in JIRA
        # expire risk acceptance on all grouped findings, make sure they are open in JIRA
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 3)
        findings = self.get_test_findings_api(test_id)
        finding_id = findings["results"][0]["id"]

        ra_data = {
            "name": "Accept: Unit test",
            "accepted_findings": [],
            "recommendation": "A",
            "recommendation_details": "recommendation 1",
            "decision": "A",
            "decision_details": "it has been decided!",
            "accepted_by": "pointy haired boss",
            "owner": 1,
            "expiration_date": "2024-12-31",
            "reactivate_expired": True,
            }

        for finding in findings["results"]:
            ra_data["accepted_findings"].append(finding["id"])

        pre_jira_status = self.get_jira_issue_status(finding_id)

        response = self.add_risk_acceptance(1, data_risk_accceptance=ra_data)
        self.assertEqual("/engagement/1", response.url)

        # We do this to update the JIRA
        for finding in ra_data["accepted_findings"]:
            self.patch_finding_api(finding, {"push_to_jira": True})

        post_jira_status = self.get_jira_issue_status(finding_id)
        self.assertNotEqual(pre_jira_status, post_jira_status)

        pre_jira_status = post_jira_status
        ra = Risk_Acceptance.objects.last()
        ra_helper.expire_now(ra)
        # We do this to update the JIRA
        for finding in ra_data["accepted_findings"]:
            self.patch_finding_api(finding, {"push_to_jira": True})

        post_jira_status = self.get_jira_issue_status(finding_id)
        self.assertNotEqual(pre_jira_status, post_jira_status)

        # by asserting full cassette is played we know all calls to JIRA have been made as expected
        self.assert_cassette_played()

    @patch("dojo.decorators.we_want_async", return_value=False)
    def test_import_grouped_reopen_expired_risk_acceptance_with_finding_sync(self, mock):
        # steps
        # import scan, make sure they are in grouped JIRA
        # risk acceptance all the grouped findings, make sure they are closed in JIRA
        # expire risk acceptance on all grouped findings, make sure they are open in JIRA
        JIRA_Instance.objects.update(finding_jira_sync=True)

        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 3)
        findings = self.get_test_findings_api(test_id)
        finding_id = findings["results"][0]["id"]

        ra_data = {
            "name": "Accept: Unit test",
            "accepted_findings": [],
            "recommendation": "A",
            "recommendation_details": "recommendation 1",
            "decision": "A",
            "decision_details": "it has been decided!",
            "accepted_by": "pointy haired boss",
            "owner": 1,
            "expiration_date": "2024-12-31",
            "reactivate_expired": True,
            }

        for finding in findings["results"]:
            ra_data["accepted_findings"].append(finding["id"])

        pre_jira_status = self.get_jira_issue_status(finding_id)

        response = self.add_risk_acceptance(1, data_risk_accceptance=ra_data)
        self.assertEqual("/engagement/1", response.url)

        # we don't do any explicit push to JIRA here as it should happen automatically

        post_jira_status = self.get_jira_issue_status(finding_id)
        self.assertNotEqual(pre_jira_status, post_jira_status)

        pre_jira_status = post_jira_status
        ra = Risk_Acceptance.objects.last()
        ra_helper.expire_now(ra)

        # we don't do any explicit push to JIRA here as it should happen automatically

        post_jira_status = self.get_jira_issue_status(finding_id)
        self.assertNotEqual(pre_jira_status, post_jira_status)

        # by asserting full cassette is played we know all calls to JIRA have been made as expected
        self.assert_cassette_played()

    def test_import_with_groups_twice_push_to_jira(self):
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 3)

        import1 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=True, verified=True)
        test_id1 = import1["test"]
        # duplicates shouldn't be sent to JIRA
        self.assert_jira_issue_count_in_test(test_id1, 0)
        self.assert_jira_group_issue_count_in_test(test_id1, 0)

    def test_import_twice_push_to_jira_push_all_issues(self):
        self.set_jira_push_all_issues(self.get_engagement(1))
        import0 = self.import_scan_with_params(self.zap_sample5_filename, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        import1 = self.import_scan_with_params(self.zap_sample5_filename, verified=True)
        test_id1 = import1["test"]
        # duplicates shouldn't be sent to JIRA
        self.assert_jira_issue_count_in_test(test_id1, 0)
        self.assert_jira_group_issue_count_in_test(test_id1, 0)

    def test_create_edit_update_finding(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        findings = self.get_test_findings_api(test_id)

        finding_id = findings["results"][0]["id"]

        # use existing finding as template, but change some fields to make it not a duplicate
        finding_details = self.get_finding_api(finding_id)
        del finding_details["id"]
        del finding_details["push_to_jira"]

        with self.subTest("New finding, no push to jira should not create a new issue"):
            finding_details["title"] = "jira api test 1"
            self.post_new_finding_api(finding_details)
            self.assert_jira_issue_count_in_test(test_id, 0)
            self.assert_jira_group_issue_count_in_test(test_id, 0)

        with self.subTest("New finding, push to jira should create a new issue"):
            finding_details["title"] = "jira api test 2"
            self.post_new_finding_api(finding_details, push_to_jira=True)
            self.assert_jira_issue_count_in_test(test_id, 1)
            self.assert_jira_group_issue_count_in_test(test_id, 0)

        with self.subTest("New finding, no push to jira should not create a new issue"):
            finding_details["title"] = "jira api test 3"
            new_finding_json = self.post_new_finding_api(finding_details)
            self.assert_jira_issue_count_in_test(test_id, 1)
            self.assert_jira_group_issue_count_in_test(test_id, 0)

        with self.subTest("Updating this new finding without push to jira should not create a new issue"):
            self.patch_finding_api(new_finding_json["id"], {"push_to_jira": False})
            self.assert_jira_issue_count_in_test(test_id, 1)
            self.assert_jira_group_issue_count_in_test(test_id, 0)

        with self.subTest("Updating this new finding with push to jira should create a new issue"):
            self.patch_finding_api(new_finding_json["id"], {"push_to_jira": True})
            self.assert_jira_issue_count_in_test(test_id, 2)
            self.assert_jira_group_issue_count_in_test(test_id, 0)

        # Only Finding Groups will have their priority synced on updates.
        # For Findings we resepect any priority change made in JIRA
        # https://github.com/DefectDojo/django-DefectDojo/pull/9571 and https://github.com/DefectDojo/django-DefectDojo/pull/12475
        with self.subTest("Changing priority of a finding should NOT be reflected in JIRA"):
            pre_jira_priority = self.get_jira_issue_priority(new_finding_json["id"])
            self.patch_finding_api(new_finding_json["id"], {"severity": "Medium"})
            self.assert_jira_issue_count_in_test(test_id, 2)
            self.assert_jira_group_issue_count_in_test(test_id, 0)
            post_jira_priority = self.get_jira_issue_priority(new_finding_json["id"])
            self.assertEqual(pre_jira_priority, post_jira_priority)

        with self.subTest("Mitigating this finding should result in a status change in JIRA"):
            pre_jira_status = self.get_jira_issue_status(new_finding_json["id"])
            self.assertEqual("Backlog", pre_jira_status.name)

            self.patch_finding_api(new_finding_json["id"], {"push_to_jira": True,
                                                            "is_mitigated": True,
                                                            "active": False})
            self.assert_jira_issue_count_in_test(test_id, 2)
            self.assert_jira_group_issue_count_in_test(test_id, 0)
            post_jira_status = self.get_jira_issue_status(new_finding_json["id"])
            self.assertEqual("Done", post_jira_status.name)

        finding_details["title"] = "jira api test 4"
        new_finding_json = self.post_new_finding_api(finding_details)
        new_finding_id = new_finding_json["id"]
        del new_finding_json["id"]

        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        self.put_finding_api(new_finding_id, new_finding_json, push_to_jira=False)
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        self.put_finding_api(new_finding_id, new_finding_json, push_to_jira=True)
        self.assert_jira_issue_count_in_test(test_id, 3)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        self.put_finding_api(new_finding_id, new_finding_json, push_to_jira=True)
        self.assert_jira_issue_count_in_test(test_id, 3)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        self.assert_cassette_played()

    def test_groups_create_edit_update_finding(self):
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        findings = self.get_test_findings_api(test_id, component_name="negotiator")

        self.assertEqual(len(findings["results"]), 2)

        with self.subTest("Pushing a finding with in a group should result in the group issue being pushed"):
            finding_details = self.get_finding_api(findings["results"][0]["id"])
            finding_group_id = findings["results"][0]["finding_groups"][0]["id"]

            del finding_details["id"]
            del finding_details["push_to_jira"]

            # push a finding should result in pushing the group instead
            self.patch_finding_api(findings["results"][0]["id"], {"push_to_jira": True, "verified": True})

            self.assert_jira_issue_count_in_test(test_id, 0)
            self.assert_jira_group_issue_count_in_test(test_id, 1)

            post_jira_status = self.get_jira_issue_status(findings["results"][0]["id"])
            self.assertEqual("Backlog", post_jira_status.name)

        with self.subTest("Pushing a different finding with in a group should result in the group issue being pushed and not a new issue being created"):
            # push second finding from the same group should not result in a new jira issue
            self.patch_finding_api(findings["results"][1]["id"], {"push_to_jira": True})
            self.assert_jira_issue_count_in_test(test_id, 0)
            self.assert_jira_group_issue_count_in_test(test_id, 1)

            post_jira_status = self.get_jira_issue_status(findings["results"][0]["id"])
            self.assertEqual("Backlog", post_jira_status.name)

        with self.subTest("Changing severity of findings in the group to Medium should result in the group issue priority being updated"):
            pre_jira_priority = self.get_jira_issue_priority(findings["results"][0]["id"])
            self.assertEqual("High", pre_jira_priority.name)

            # change only 1 to medium, the other one remains high
            self.patch_finding_api(findings["results"][0]["id"], {"severity": "Medium", "push_to_jira": True})
            post_jira_priority = self.get_jira_issue_priority(findings["results"][0]["id"])
            self.assertEqual("High", post_jira_priority.name)

            # both are Medium now
            self.patch_finding_api(findings["results"][1]["id"], {"severity": "Medium", "push_to_jira": True})
            post_jira_priority = self.get_jira_issue_priority(findings["results"][1]["id"])
            self.assertEqual("Medium", post_jira_priority.name)

            # revert to not mess up the following tests
            self.patch_finding_api(findings["results"][0]["id"], {"severity": "High", "push_to_jira": True})
            post_jira_priority = self.get_jira_issue_priority(findings["results"][1]["id"])
            self.assertEqual("High", post_jira_priority.name)

        with self.subTest("Closing all findings in the group should result in the group issue being closed and priority being updated"):
            pre_jira_status = self.get_jira_issue_status(findings["results"][0]["id"])
            pre_jira_priority = self.get_jira_issue_priority(findings["results"][0]["id"])
            self.assertEqual("High", pre_jira_priority.name)
            self.assertEqual("Backlog", pre_jira_status.name)

            # close both findings
            self.patch_finding_api(findings["results"][0]["id"], {"active": False, "is_mitigated": True, "push_to_jira": True})
            self.patch_finding_api(findings["results"][1]["id"], {"active": False, "is_mitigated": True, "push_to_jira": True})

            post_jira_status = self.get_jira_issue_status(findings["results"][0]["id"])
            post_jira_priority = self.get_jira_issue_priority(findings["results"][0]["id"])
            self.assertEqual("Lowest", post_jira_priority.name)
            self.assertEqual("Done", post_jira_status.name)

        with self.subTest("Updating group findings to have no active findings above threshold should result in the group issue being set to the lowest priority and remain inactive"):
            # reopen 1 finding, but make it below the threshold
            self.patch_finding_api(findings["results"][0]["id"], {"active": True, "is_mitigated": False, "severity": "Info", "push_to_jira": True})

            post_jira_status = self.get_jira_issue_status(findings["results"][0]["id"])
            post_jira_priority = self.get_jira_issue_priority(findings["results"][0]["id"])
            self.assertEqual("Lowest", post_jira_priority.name)
            self.assertEqual("Done", post_jira_status.name)

            # reopen the other finding
            self.patch_finding_api(findings["results"][1]["id"], {"active": True, "is_mitigated": False, "severity": "Medium", "push_to_jira": True})
            post_jira_status = self.get_jira_issue_status(findings["results"][1]["id"])
            post_jira_priority = self.get_jira_issue_priority(findings["results"][1]["id"])
            self.assertEqual("Medium", post_jira_priority.name)
            self.assertEqual("Backlog", post_jira_status.name)

        with self.subTest("Opening a finding without push_to_jira should not result in a new issue being created"):
            # new finding, not pushed to JIRA
            # use existing finding as template, but change some fields to make it not a duplicate
            self.get_finding_api(findings["results"][0]["id"])

            finding_details["title"] = "jira api test 1"
            self.post_new_finding_api(finding_details)
            self.assert_jira_issue_count_in_test(test_id, 0)
            self.assert_jira_group_issue_count_in_test(test_id, 1)

        with self.subTest("Opening a finding in the same group without push_to_jira should not result in a new issue being created"):
            # another new finding, pushed to JIRA
            # same component_name, but not yet in a group, so finding pushed to JIRA

            finding_details["title"] = "jira api test 2"
            new_finding_json = self.post_new_finding_api(finding_details, push_to_jira=True)
            self.assert_jira_issue_count_in_test(test_id, 1)
            self.assert_jira_group_issue_count_in_test(test_id, 1)

            # no way to set finding group easily via API yet
            Finding_Group.objects.get(id=finding_group_id).findings.add(Finding.objects.get(id=new_finding_json["id"]))

            self.patch_finding_api(new_finding_json["id"], {"push_to_jira": True})

            self.assert_jira_issue_count_in_test(test_id, 1)
            self.assert_jira_group_issue_count_in_test(test_id, 1)

        with self.subTest("Opening a finding with different fields resulting in a diffrent group should result in a new group issue being created"):
            # another new finding, pushed to JIRA, different component_name / different group
            finding_details["title"] = "jira api test 3"
            finding_details["component_name"] = "pg"
            new_finding_json = self.post_new_finding_api(finding_details)
            self.assert_jira_issue_count_in_test(test_id, 1)
            self.assert_jira_group_issue_count_in_test(test_id, 1)

            findings = self.get_test_findings_api(test_id, component_name="pg")

            finding_group_id = findings["results"][0]["finding_groups"][0]["id"]

            # no way to set finding group easily via API yet
            Finding_Group.objects.get(id=finding_group_id).findings.add(Finding.objects.get(id=new_finding_json["id"]))

            self.patch_finding_api(new_finding_json["id"], {"push_to_jira": True})

            self.assert_jira_issue_count_in_test(test_id, 1)
            self.assert_jira_group_issue_count_in_test(test_id, 2)

        self.assert_cassette_played()

    def test_import_with_push_to_jira_add_comment(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        findings = self.get_test_findings_api(test_id)

        finding_id = findings["results"][0]["id"]

        self.post_finding_notes_api(finding_id, "testing note. creating it and pushing it to JIRA")
        self.patch_finding_api(finding_id, {"push_to_jira": True})
        # Make sure the number of comments match
        self.assertEqual(len(self.get_jira_comments(finding_id)), 1)
        # by asserting full cassette is played we know all calls to JIRA have been made as expected
        self.assert_cassette_played()

    def test_import_add_comments_then_push_to_jira(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=False, verified=True)
        test_id = import0["test"]

        findings = self.get_test_findings_api(test_id)

        finding_id = findings["results"][0]["id"]

        self.post_finding_notes_api(finding_id, "testing note. creating it and pushing it to JIRA")
        self.post_finding_notes_api(finding_id, "testing second note. creating it and pushing it to JIRA")
        self.patch_finding_api(finding_id, {"push_to_jira": True})

        self.assert_jira_issue_count_in_test(test_id, 1)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # Make sure the number of comments match
        self.assertEqual(len(self.get_jira_comments(finding_id)), 2)
        # by asserting full cassette is played we know all calls to JIRA have been made as expected
        self.assert_cassette_played()

    def test_import_with_push_to_jira_add_tags(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        findings = self.get_test_findings_api(test_id)

        finding = Finding.objects.get(id=findings["results"][0]["id"])

        tags = ["tag1", "tag2"]
        self.post_finding_tags_api(finding.id, tags)
        self.patch_finding_api(finding.id, {"push_to_jira": True})

        # Connect to jira to get the new issue
        jira_instance = jira_helper.get_jira_instance(finding)
        jira = jira_helper.get_jira_connection(jira_instance)
        issue = jira.issue(finding.jira_issue.jira_id)

        # Assert that the tags match
        self.assertEqual(issue.fields.labels, tags)

        # by asserting full cassette is played we know all calls to JIRA have been made as expected
        self.assert_cassette_played()

    def test_import_with_push_to_jira_update_tags(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        findings = self.get_test_findings_api(test_id)

        finding = Finding.objects.get(id=findings["results"][0]["id"])

        tags = ["tag1", "tag2"]
        self.post_finding_tags_api(finding.id, tags)
        self.patch_finding_api(finding.id, {"push_to_jira": True})

        # Connect to jira to get the new issue
        jira_instance = jira_helper.get_jira_instance(finding)
        jira = jira_helper.get_jira_connection(jira_instance)
        issue = jira.issue(finding.jira_issue.jira_id)

        # Assert that the tags match
        self.assertEqual(issue.fields.labels, tags)

        tags_new = [*tags, "tag3", "tag4"]
        self.post_finding_tags_api(finding.id, tags_new)
        self.patch_finding_api(finding.id, {"push_to_jira": True})

        # Connect to jira to get the new issue
        jira_instance = jira_helper.get_jira_instance(finding)
        jira = jira_helper.get_jira_connection(jira_instance)
        issue = jira.issue(finding.jira_issue.jira_id)

        # Assert that the tags match
        self.assertEqual(issue.fields.labels, tags_new)

        # by asserting full cassette is played we know all calls to JIRA have been made as expected
        self.assert_cassette_played()

    @toggle_system_setting_boolean("enforce_verified_status", True)  # noqa: FBT003
    @toggle_system_setting_boolean("enforce_verified_status_jira", True)  # noqa: FBT003
    @with_system_setting("jira_minimum_severity", "Low")
    def test_import_with_push_to_jira_not_verified_enforced_verified_globally_true_enforced_verified_jira_true(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, verified=False)
        test_id = import0["test"]
        # This scan file has two active findings, so we should not push either of them
        self.assert_jira_issue_count_in_test(test_id, 0)

        # Verfied findings should be pushed, different scan to avoid dedupe interference
        import0 = self.import_scan_with_params(self.clair_few_findings, scan_type="Clair Scan", push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 4)

        # by asserting full cassette is played we know all calls to JIRA have been made as expected
        self.assert_cassette_played()

    @toggle_system_setting_boolean("enforce_verified_status", True)  # noqa: FBT003
    @toggle_system_setting_boolean("enforce_verified_status_jira", False)  # noqa: FBT003
    @with_system_setting("jira_minimum_severity", "Low")
    def test_import_with_push_to_jira_not_verified_enforced_verified_globally_true_enforced_verified_jira_false(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, verified=False)
        test_id = import0["test"]
        # This scan file has two active findings, so we should not push either of them
        self.assert_jira_issue_count_in_test(test_id, 0)

        # Verfied findings should be pushed, different scan to avoid dedupe interference
        import0 = self.import_scan_with_params(self.clair_few_findings, scan_type="Clair Scan", push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 4)
        # by asserting full cassette is played we know all calls to JIRA have been made as expected

        self.assert_cassette_played()

    @toggle_system_setting_boolean("enforce_verified_status", False)  # noqa: FBT003
    @toggle_system_setting_boolean("enforce_verified_status_jira", True)  # noqa: FBT003
    @with_system_setting("jira_minimum_severity", "Low")
    def test_import_with_push_to_jira_not_verified_enforced_verified_globally_false_enforced_verified_jira_true(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, verified=False)
        test_id = import0["test"]
        # This scan file has two active findings, so we should not push either of them
        self.assert_jira_issue_count_in_test(test_id, 0)

        # Verfied findings should be pushed, different scan to avoid dedupe interference
        import0 = self.import_scan_with_params(self.clair_few_findings, scan_type="Clair Scan", push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_issue_count_in_test(test_id, 4)

        # by asserting full cassette is played we know all calls to JIRA have been made as expected
        self.assert_cassette_played()

    @toggle_system_setting_boolean("enforce_verified_status", False)  # noqa: FBT003
    @toggle_system_setting_boolean("enforce_verified_status_jira", False)  # noqa: FBT003
    @with_system_setting("jira_minimum_severity", "Low")
    def test_import_with_push_to_jira_not_verified_enforced_verified_globally_false_enforced_verified_jira_false(self):
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, verified=False)
        test_id = import0["test"]
        # This scan file has two active findings, so we should not push both of them
        self.assert_jira_issue_count_in_test(test_id, 2)
        # by asserting full cassette is played we know all calls to JIRA have been made as expected
        self.assert_cassette_played()

    @toggle_system_setting_boolean("enforce_verified_status", True)  # noqa: FBT003
    @toggle_system_setting_boolean("enforce_verified_status_jira", True)  # noqa: FBT003
    def test_groups_import_with_push_to_jira_not_verified_enforced_verified_globally_true_enforced_verified_jira_true(self):
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=True, verified=False)
        test_id = import0["test"]
        # No verified findings, means no groups pushed to JIRA
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        import0 = self.import_scan_with_params(self.npm_groups_sample_filename2, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_group_issue_count_in_test(test_id, 3)

        # by asserting full cassette is played we know all calls to JIRA have been made as expected
        self.assert_cassette_played()

    @toggle_system_setting_boolean("enforce_verified_status", True)  # noqa: FBT003
    @toggle_system_setting_boolean("enforce_verified_status_jira", False)  # noqa: FBT003
    def test_groups_import_with_push_to_jira_not_verified_enforced_verified_globally_true_enforced_verified_jira_false(self):
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=True, verified=False)
        test_id = import0["test"]
        # No verified findings, means no groups pushed to JIRA
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        import0 = self.import_scan_with_params(self.npm_groups_sample_filename2, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_group_issue_count_in_test(test_id, 3)
        # by asserting full cassette is played we know all calls to JIRA have been made as expected

        self.assert_cassette_played()

    @toggle_system_setting_boolean("enforce_verified_status", False)  # noqa: FBT003
    @toggle_system_setting_boolean("enforce_verified_status_jira", True)  # noqa: FBT003
    def test_groups_import_with_push_to_jira_not_verified_enforced_verified_globally_false_enforced_verified_jira_true(self):
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=True, verified=False)
        test_id = import0["test"]
        # No verified findings, means no groups pushed to JIRA
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        import0 = self.import_scan_with_params(self.npm_groups_sample_filename2, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_group_issue_count_in_test(test_id, 3)

        # by asserting full cassette is played we know all calls to JIRA have been made as expected
        self.assert_cassette_played()

    @toggle_system_setting_boolean("enforce_verified_status", False)  # noqa: FBT003
    @toggle_system_setting_boolean("enforce_verified_status_jira", False)  # noqa: FBT003
    @with_system_setting("jira_minimum_severity", "Low")
    def test_groups_import_with_push_to_jira_not_verified_enforced_verified_globally_false_enforced_verified_jira_false(self):
        import0 = self.import_scan_with_params(self.npm_groups_sample_filename, scan_type="NPM Audit Scan", group_by="component_name+component_version", push_to_jira=True, verified=True)
        test_id = import0["test"]
        self.assert_jira_group_issue_count_in_test(test_id, 3)
        # by asserting full cassette is played we know all calls to JIRA have been made as expected
        self.assert_cassette_played()

    def test_engagement_epic_creation(self):
        eng = self.get_engagement(3)
        # Set epic_mapping to true
        self.toggle_jira_project_epic_mapping(eng, value=True)
        self.create_engagement_epic(eng)
        self.assertTrue(eng.has_jira_issue)

        self.assert_cassette_played()

    def test_engagement_epic_mapping_enabled_create_epic_and_push_findings(self):
        eng = self.get_engagement(3)
        # Set epic_mapping to true
        self.toggle_jira_project_epic_mapping(eng, value=True)
        self.create_engagement_epic(eng)
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, engagement=3, verified=True)
        test_id = import0["test"]
        # Correct number of issues are pushed to jira
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # Correct number of issues are in the epic
        self.assert_epic_issue_count(eng, 2)
        # Ensure issue are actually in the correct epic
        finding = Finding.objects.filter(test__id=test_id).first()
        self.assert_jira_issue_in_epic(finding, eng, issue_in_epic=True)

        self.assert_cassette_played()

    def test_engagement_epic_mapping_enabled_no_epic_and_push_findings(self):
        eng = self.get_engagement(3)
        # Set epic_mapping to true
        self.toggle_jira_project_epic_mapping(eng, value=True)
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, engagement=3, verified=True)
        test_id = import0["test"]
        # Correct number of issues are pushed to jira
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # Correct number of issues are in the epic
        self.assert_epic_issue_count(eng, 0)
        # Ensure issue are actually not in the correct epic
        finding = Finding.objects.filter(test__id=test_id).first()
        self.assert_jira_issue_in_epic(finding, eng, issue_in_epic=False)

        self.assert_cassette_played()

    def test_engagement_epic_mapping_disabled_create_epic_and_push_findings(self):
        eng = self.get_engagement(3)
        # Set epic_mapping to true
        self.toggle_jira_project_epic_mapping(eng, value=False)
        self.create_engagement_epic(eng)
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, engagement=3, verified=True)
        test_id = import0["test"]
        # Correct number of issues are pushed to jira
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # Correct number of issues are in the epic
        self.assert_epic_issue_count(eng, 0)
        # Ensure issue are actually in the correct epic
        finding = Finding.objects.filter(test__id=test_id).first()
        self.assert_jira_issue_in_epic(finding, eng, issue_in_epic=False)

        self.assert_cassette_played()

    def test_engagement_epic_mapping_disabled_no_epic_and_push_findings(self):
        eng = self.get_engagement(3)
        # Set epic_mapping to true
        self.toggle_jira_project_epic_mapping(eng, value=False)
        import0 = self.import_scan_with_params(self.zap_sample5_filename, push_to_jira=True, engagement=3, verified=True)
        test_id = import0["test"]
        # Correct number of issues are pushed to jira
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # Correct number of issues are in the epic
        self.assert_epic_issue_count(eng, 0)
        # Ensure issue are actually not in the correct epic
        finding = Finding.objects.filter(test__id=test_id).first()
        self.assert_jira_issue_in_epic(finding, eng, issue_in_epic=False)

        self.assert_cassette_played()

    @patch("dojo.jira_link.helper.can_be_pushed_to_jira", return_value=(True, None, None))
    @patch("dojo.jira_link.helper.is_push_all_issues", return_value=False)
    @patch("dojo.jira_link.helper.push_to_jira", return_value=None)
    @patch("dojo.notifications.helper.send_webhooks_notification")
    def test_bulk_edit_mixed_findings_and_groups_jira_push_bug(self, mock_webhooks, mock_push_to_jira, mock_is_push_all_issues, mock_can_be_pushed):
        """
        Test the bug in bulk edit: when bulk editing findings where some are in groups
        and some are not, individual findings should still be pushed to JIRA even if
        groups are also pushed.

        Bug: If finding groups are pushed to JIRA (groups_pushed_to_jira=True),
        then individual findings are skipped due to the condition:
        `if not groups_pushed_to_jira and (...)`
        """
        # Import scan with groups but don't push to JIRA initially
        import0 = self.import_scan_with_params(
            self.npm_groups_sample_filename,
            scan_type="NPM Audit Scan",
            group_by="component_name+component_version",
            push_to_jira=False,
            verified=True,
        )
        test_id = import0["test"]

        # Verify no JIRA issues were created during import
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        # Get the findings and finding groups created
        Finding.objects.filter(test__id=test_id).order_by("id")
        finding_groups = Finding_Group.objects.filter(test__id=test_id)

        # Create mixed scenario: some findings in groups, some ungrouped
        # Remove one entire group to create ungrouped findings
        if finding_groups.exists():
            # Remove all findings from the first group and delete the group
            group_to_remove = finding_groups.first()
            list(group_to_remove.findings.all())
            # Remove all findings from this group, making them ungrouped
            group_to_remove.findings.clear()
            # Delete the empty group
            group_to_remove.delete()

        # Verify we now have both grouped and ungrouped findings
        # Note: finding_group is a cached property, so we need to check if findings are in any group
        all_findings = Finding.objects.filter(test__id=test_id)
        grouped_findings = [f for f in all_findings if f.finding_group is not None]
        ungrouped_findings = [f for f in all_findings if f.finding_group is None]

        self.assertGreater(len(grouped_findings), 0, "Should have some grouped findings")
        self.assertGreater(len(ungrouped_findings), 0, "Should have some ungrouped findings")

        # Use Django test client instead of RequestFactory for proper auth

        # Prepare bulk edit request data
        # Get the current finding IDs after group modifications
        current_findings = Finding.objects.filter(test__id=test_id)
        all_finding_ids = [str(f.id) for f in current_findings]

        # Login as admin user who has all permissions
        admin_user = get_user_model().objects.get(username="admin")
        self.client.force_login(admin_user)

        post_data = {
            "finding_to_update": all_finding_ids,
            "push_to_jira": "on",  # Checkbox value when checked
            # Form validation fields - all optional but need to be present
            "severity": "",
            "active": "",
            "verified": "",
            "false_p": "",
            "duplicate": "",
            "out_of_scope": "",
            "is_mitigated": "",
            "status": "",  # Required for form structure
        }

        # Perform bulk edit using test client
        self.client.post("/finding/bulk", post_data)

        # Analyze what was pushed to JIRA
        group_calls = [call for call in mock_push_to_jira.call_args_list if isinstance(call[0][0], Finding_Group)]
        individual_calls = [call for call in mock_push_to_jira.call_args_list if isinstance(call[0][0], Finding)]

        # Test expectations - both groups AND individual findings should be pushed
        self.assertGreater(len(group_calls), 0, "Finding groups should be pushed to JIRA")
        self.assertGreater(len(individual_calls), 0, "Individual findings should also be pushed to JIRA despite groups being pushed")

        # Verify the fix: we should have exactly 2 groups + 2 individual findings pushed
        self.assertEqual(len(group_calls), 2, "Expected 2 finding groups to be pushed")
        self.assertEqual(len(individual_calls), 2, "Expected 2 individual findings to be pushed")

    def _bulk_edit_finding_groups_without_checkbox(self):
        """
        Helper: sets up a mixed grouped/ungrouped scenario and performs a bulk edit
        WITHOUT the push_to_jira checkbox. Returns the test_id and finding IDs used.
        """
        # Import scan with groups but don't push to JIRA initially
        import0 = self.import_scan_with_params(
            self.npm_groups_sample_filename,
            scan_type="NPM Audit Scan",
            group_by="component_name+component_version",
            push_to_jira=False,
            verified=True,
        )
        test_id = import0["test"]

        # Verify no JIRA issues were created during import
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 0)

        # Get the finding groups created
        finding_groups = Finding_Group.objects.filter(test__id=test_id)

        # Create mixed scenario: some findings in groups, some ungrouped
        if finding_groups.exists():
            group_to_remove = finding_groups.first()
            group_to_remove.findings.clear()
            group_to_remove.delete()

        # Verify we now have both grouped and ungrouped findings
        all_findings = Finding.objects.filter(test__id=test_id)
        grouped_findings = [f for f in all_findings if f.finding_group is not None]
        ungrouped_findings = [f for f in all_findings if f.finding_group is None]

        self.assertGreater(len(grouped_findings), 0, "Should have some grouped findings")
        self.assertGreater(len(ungrouped_findings), 0, "Should have some ungrouped findings")

        current_findings = Finding.objects.filter(test__id=test_id)
        all_finding_ids = [str(f.id) for f in current_findings]

        admin_user = get_user_model().objects.get(username="admin")
        self.client.force_login(admin_user)

        # NOTE: push_to_jira is NOT in the post data -- the checkbox is unchecked
        post_data = {
            "finding_to_update": all_finding_ids,
            "severity": "",
            "active": "",
            "verified": "",
            "false_p": "",
            "duplicate": "",
            "out_of_scope": "",
            "is_mitigated": "",
            "status": "",
        }

        self.client.post("/finding/bulk", post_data)

    @patch("dojo.jira_link.helper.can_be_pushed_to_jira", return_value=(True, None, None))
    @patch("dojo.jira_link.helper.is_push_all_issues", return_value=True)
    @patch("dojo.jira_link.helper.push_to_jira", return_value=None)
    @patch("dojo.notifications.helper.WebhookNotificationManger.send_webhooks_notification")
    def test_bulk_edit_push_all_issues_pushes_finding_groups(self, mock_webhooks, mock_push_to_jira, mock_is_push_all_issues, mock_can_be_pushed):
        """
        When push_all_issues is enabled on the JIRA project, bulk editing findings
        should push finding groups to JIRA even without the push_to_jira checkbox.
        """
        self._bulk_edit_finding_groups_without_checkbox()

        group_calls = [call for call in mock_push_to_jira.call_args_list if isinstance(call[0][0], Finding_Group)]
        individual_calls = [call for call in mock_push_to_jira.call_args_list if isinstance(call[0][0], Finding)]

        self.assertGreater(len(group_calls), 0, "Finding groups should be pushed when push_all_issues is enabled")
        self.assertGreater(len(individual_calls), 0, "Individual ungrouped findings should be pushed when push_all_issues is enabled")

        self.assertEqual(len(group_calls), 2, "Expected 2 finding groups to be pushed")
        self.assertEqual(len(individual_calls), 2, "Expected 2 individual findings to be pushed")

    @patch("dojo.jira_link.helper.can_be_pushed_to_jira", return_value=(True, None, None))
    @patch("dojo.jira_link.helper.is_keep_in_sync_with_jira", return_value=True)
    @patch("dojo.jira_link.helper.is_push_all_issues", return_value=False)
    @patch("dojo.jira_link.helper.push_to_jira", return_value=None)
    @patch("dojo.notifications.helper.WebhookNotificationManger.send_webhooks_notification")
    def test_bulk_edit_keep_in_sync_pushes_finding_groups(self, mock_webhooks, mock_push_to_jira, mock_is_push_all_issues, mock_is_keep_in_sync, mock_can_be_pushed):
        """
        When keep_in_sync_with_jira (finding_jira_sync) is enabled on the JIRA instance,
        bulk editing findings should push finding groups to JIRA even without the
        push_to_jira checkbox.
        """
        self._bulk_edit_finding_groups_without_checkbox()

        group_calls = [call for call in mock_push_to_jira.call_args_list if isinstance(call[0][0], Finding_Group)]
        individual_calls = [call for call in mock_push_to_jira.call_args_list if isinstance(call[0][0], Finding)]

        self.assertGreater(len(group_calls), 0, "Finding groups should be pushed when keep_in_sync is enabled")
        self.assertGreater(len(individual_calls), 0, "Individual ungrouped findings should be pushed when keep_in_sync is enabled")

        self.assertEqual(len(group_calls), 2, "Expected 2 finding groups to be pushed")
        self.assertEqual(len(individual_calls), 2, "Expected 2 individual findings to be pushed")

    def test_keep_sync_push_finding_then_update_individual_finding_with_no_push(self):
        """
        With keep_sync enabled, import a scan with push_to_jira=True, then update one of the
        findings with push_to_jira=False, but keep_sync enabled, should update the issue in JIRA
        """
        # Set the finding sync setting
        import0 = self.import_scan_with_params(
            self.generic_one_finding_with_component_name,
            scan_type="Generic Findings Import",
            push_to_jira=True,
            verified=True,
        )
        test_id = import0["test"]
        test = Test.objects.get(id=test_id)
        self.assert_jira_issue_count_in_test(test_id, 1)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # Enable the finding sync
        self.toggle_jira_finding_sync(test, value=True)
        # Get one of the findings
        finding_id = self.get_test_findings_api(test_id)["results"][0]["id"]
        # Ensure the status is what we expect before the update
        pre_jira_status = self.get_jira_issue_status(finding_id)
        self.assertEqual("Backlog", pre_jira_status.name)
        # Make the update to the finding
        self.patch_finding_api(finding_id, {"push_to_jira": False, "is_mitigated": True})
        # Verify that the status did in fact change
        post_jira_status = self.get_jira_issue_status(finding_id)
        self.assertEqual("Done", post_jira_status.name)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_keep_sync_push_finding_then_reimport_with_no_push(self):
        """
        With keep_sync enabled, import a scan with push_to_jira=True, then reimport a second
        scan with push_to_jira=False that closes one of the findings, should update the issue in JIRA
        """
        # Set the finding sync setting
        import0 = self.import_scan_with_params(
            self.generic_two_findings_same_component_name,
            scan_type="Generic Findings Import",
            push_to_jira=True,
            verified=True,
        )
        test_id = import0["test"]
        test = Test.objects.get(id=test_id)
        self.assert_jira_issue_count_in_test(test_id, 2)
        self.assert_jira_group_issue_count_in_test(test_id, 0)
        # Enable the finding sync
        self.toggle_jira_finding_sync(test, value=True)
        # Get the finding that will be closing in the next reimport
        finding_id = self.get_test_findings_api(test_id, severity="Critical")["results"][0]["id"]
        # Ensure the status is what we expect before the update
        pre_jira_status = self.get_jira_issue_status(finding_id)
        self.assertEqual("Backlog", pre_jira_status.name)
        # Reimport with a different file that has one finding closed, but push_to_jira=False
        import0 = self.reimport_scan_with_params(
            test_id,
            self.generic_one_finding_with_component_name,
            scan_type="Generic Findings Import",
            push_to_jira=False,
            verified=True,
            close_old_findings=True,
        )
        # Verify that the status did in fact change
        post_jira_status = self.get_jira_issue_status(finding_id)
        self.assertEqual("Done", post_jira_status.name)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_keep_sync_push_finding_groups_then_reimport_empty_file_with_no_push_change_status(self):
        """
        With keep_sync enabled, import a scan with push_to_jira=True that creates a group, then reimport
        an empty scan with push_to_jira=False that closes the finding in the group, should update the
        issue in JIRA to closed
        """
        # Set the finding sync setting
        import0 = self.import_scan_with_params(
            self.generic_two_findings_same_component_name,
            scan_type="Generic Findings Import",
            push_to_jira=True,
            verified=True,
            group_by="component_name",
        )
        test_id = import0["test"]
        test = Test.objects.get(id=test_id)
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 1)
        # Enable the finding sync
        self.toggle_jira_finding_sync(test, value=True)
        # Get the finding that will be closing in the next reimport
        finding_id = self.get_test_findings_api(test_id, severity="Critical")["results"][0]["id"]
        # Ensure the status is what we expect before the update
        pre_jira_status = self.get_jira_issue_status(finding_id)
        self.assertEqual("Backlog", pre_jira_status.name)
        # Reimport with a different file that has one finding closed, but push_to_jira=False
        import0 = self.reimport_scan_with_params(
            test_id,
            self.generic_report_with_findings,
            scan_type="Generic Findings Import",
            push_to_jira=False,
            verified=True,
            close_old_findings=True,
            group_by="component_name",
        )
        # Verify that the status did in fact change
        post_jira_status = self.get_jira_issue_status(finding_id)
        self.assertEqual("Done", post_jira_status.name)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_keep_sync_push_finding_groups_then_reimport_empty_file_with_no_push_change_priority(self):
        """
        With keep_sync enabled, import a scan with push_to_jira=True that creates a group, then reimport
        an empty scan with push_to_jira=False that closes the finding in the group, this should leave the
        the high severity finding in the group, and reduce the priority from Critical to High
        """
        # Set the finding sync setting
        import0 = self.import_scan_with_params(
            self.generic_two_findings_same_component_name,
            scan_type="Generic Findings Import",
            push_to_jira=True,
            verified=True,
            group_by="component_name",
        )
        test_id = import0["test"]
        test = Test.objects.get(id=test_id)
        self.assert_jira_issue_count_in_test(test_id, 0)
        self.assert_jira_group_issue_count_in_test(test_id, 1)
        # Enable the finding sync
        self.toggle_jira_finding_sync(test, value=True)
        # Get the finding that will stay open in the next reimport
        finding_id = self.get_test_findings_api(test_id, severity="High")["results"][0]["id"]
        # Get the priority that we are starting out with
        pre_jira_priority = self.get_jira_issue_priority(finding_id)
        self.assertEqual("Highest", pre_jira_priority.name)
        # Reimport with a different file that has one finding closed, but push_to_jira=False
        import0 = self.reimport_scan_with_params(
            test_id,
            self.generic_one_finding_with_component_name,
            scan_type="Generic Findings Import",
            push_to_jira=False,
            verified=True,
            close_old_findings=True,
            group_by="component_name",
        )
        # Verify that the priority did in fact change
        post_jira_priority = self.get_jira_issue_priority(finding_id)
        self.assertEqual("High", post_jira_priority.name)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    # creation of epic via the UI is already tested in test_jira_config_engagement_epic, so
    # we take a shortcut here as creating an engagement with epic mapping via the API is not implemented yet
    def create_engagement_epic(self, engagement):
        with impersonate(self.testuser):
            return jira_helper.add_epic(engagement.id)

    def assert_epic_issue_count(self, engagement, count):
        jira_issues = self.get_epic_issues(engagement)
        self.assertEqual(count, len(jira_issues))

    def _test_setup_jira_project_for_engagement(self) -> dict:
        import_reimport_config = {
            "active": True,
            "verified": True,
            "product_type_name": "Some Product Type",
            "product_name": "Jira Product (Not Configured)",
            "engagement_name": "Jira Engagement",
            "engagement": None,  # This is hardcoded on the test function, so lets just null it out
            "auto_create_context": True,
        }
        # First have a regular import create all the things
        import0 = self.import_scan_with_params(
            self.zap_sample5_filename,
            **import_reimport_config,
        )
        test_id = import0["test"]
        test = Test.objects.get(id=test_id)
        engagement = test.engagement
        # Ensure we have push to jira settings set as false here (.first fetches the most recent object)
        self.assertFalse(test.test_import_set.first().import_settings["push_to_jira"], "Expected push_to_jira to be False since no Jira project is configured")
        # Now set up the jira instance and project, and reimport the same report again with the same parameters, which should now fetch the jira project from the engagement and set push_to_jira to True in the import settings
        JIRA_Project.objects.create(
            jira_instance=JIRA_Instance.objects.first(),
            project_key="TEST",
            engagement=engagement,
            push_all_issues=True,
        )
        # Double check we have no jira findings
        self.assert_jira_issue_count_in_test(test_id, 0)

        return import_reimport_config

    # Disable deduplication here because it keeps getting in the way of us properly testing that
    # findings are pushed to jira on reimport, since the same report is being imported twice in
    # this test and deduplication will prevent the second import from creating any findings at all,
    # which means no jira issues will be created on the second import, which is what we need to assert
    # that the jira project is being fetched correctly and push_to_jira is being set to True in the import settings
    @toggle_system_setting_boolean("enable_deduplication", False)  # noqa: FBT003
    def test_import_auto_create_context_fetches_all_objects_for_push_to_jira(self):
        """
        This test is responsible for ensuring that all related objects in auto context are fetched appropriately.
        To test this, we will first set up a jira instance with a project configured at the engagement level only.
        It is not really important that we test that findings are pushed to jira here, but we can assert that the
        import history import settings reflect that the viewset was given a "True" value for push_to_jira,
        which is only possible if the engagement's jira project was correctly fetched before the serializer was invoked.
        """
        import_reimport_config = self._test_setup_jira_project_for_engagement()
        # Not run the import again
        import1 = self.import_scan_with_params(
            self.zap_sample5_filename,
            **import_reimport_config,
        )
        test_id = import1["test"]
        test = Test.objects.get(id=test_id)
        # We should now have push_to_jira set to True in the import settings due to the jira project being on the engagement
        self.assertTrue(test.test_import_set.first().import_settings["push_to_jira"], "Expected push_to_jira to be True since a Jira project is configured on the engagement")
        # Make sure we actually pushed something to jira
        self.assert_jira_issue_count_in_test(test_id, 2)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_reimport_auto_create_context_fetches_all_objects_for_push_to_jira(self):
        """
        This test is responsible for ensuring that all related objects in auto context are fetched appropriately.
        To test this, we will first set up a jira instance with a project configured at the engagement level only.
        It is not really important that we test that findings are pushed to jira here, but we can assert that the
        import history import settings reflect that the viewset was given a "True" value for push_to_jira,
        which is only possible if the engagement's jira project was correctly fetched before the serializer was invoked.
        """
        import_reimport_config = self._test_setup_jira_project_for_engagement()
        # Not run the import again
        import1 = self.reimport_scan_with_params(
            import_reimport_config.pop("test_id", None),
            self.zap_sample5_filename,
            **import_reimport_config,
        )
        test_id = import1["test"]
        test = Test.objects.get(id=test_id)
        # We should now have push_to_jira set to True in the import settings due to the jira project being on the engagement
        self.assertTrue(test.test_import_set.first().import_settings["push_to_jira"], "Expected push_to_jira to be True since a Jira project is configured on the engagement")
        # Make sure we actually pushed something to jira
        self.assert_jira_issue_count_in_test(test_id, 2)
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()
