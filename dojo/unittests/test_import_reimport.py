from dojo.models import User, Endpoint, Notes
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APITestCase, APIClient
import json
from defusedxml import ElementTree
import logging


logger = logging.getLogger(__name__)


class DedupeTest(APITestCase):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        # TODO remove __init__ if it does nothing...
        APITestCase.__init__(self, *args, **kwargs)

    def setUp(self):
        testuser = User.objects.get(username='admin')
        token = Token.objects.get(user=testuser)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
        # self.url = reverse(self.viewname + '-list')

        self.scans_path = 'dojo/unittests/scans/zap/'
        self.zap_sample1_filename = self.scans_path + 'zap_sample.xml'
        self.zap_sample2_filename = self.scans_path + 'zap_sample_updated.xml'
        self.zap_sample3_filename = self.scans_path + 'zap_sample_severity_endpoint_updated.xml'
        self.zap_sample4_filename = self.scans_path + 'zap_sample_all_endpoints_updated.xml'
        self.zap_sample1_xml = ElementTree.parse(open(self.zap_sample1_filename))
        self.zap_sample2_xml = ElementTree.parse(open(self.zap_sample2_filename))
        self.zap_sample1_count_above_threshold = 3
        self.zap_sample2_count_above_threshold = 3
        self.zap_sample3_count_above_threshold = 3
        self.zap_sample4_count_above_threshold = 3

    def import_scan(self, payload):
        response = self.client.post(reverse('importscan-list'), payload)
        self.assertEqual(201, response.status_code)
        return json.loads(response.content)

    def reimport_scan(self, payload):
        response = self.client.post(reverse('reimportscan-list'), payload)
        self.assertEqual(201, response.status_code)
        return json.loads(response.content)

    def get_test(self, test_id):
        response = self.client.get(reverse('test-list') + '%s/' % test_id, format='json')
        self.assertEqual(200, response.status_code)
        # print('test.content: ', response.content)
        return json.loads(response.content)

    def get_test_findings(self, test_id, active=None, verified=None):
        payload = {'test': test_id}
        if active is not None:
            payload['active'] = active
        if verified is not None:
            payload['verified'] = verified

        logger.debug('getting findings for test: %s', payload)

        response = self.client.get(reverse('finding-list'), payload, format='json')
        self.assertEqual(200, response.status_code)
        # print('findings.content: ', response.content)
        return json.loads(response.content)

    def log_finding_summary(self, findings_content_json):
        # print('summary')
        # print(findings_content_json)
        # print(findings_content_json['count'])

        if not findings_content_json or findings_content_json['count'] == 0:
            logger.debug('no findings')

        for finding in findings_content_json['results']:
            logger.debug(str(finding['id']) + ': active: ' + str(finding['active']) + ': verified: ' + str(finding['verified']) +
                     ': is_Mitigated: ' + str(finding['is_Mitigated']) + ": notes: " + str([n['id'] for n in finding['notes']]) +
                     ": endpoints: " + str(finding['endpoints']))

        for ep in Endpoint.objects.all():
            logger.debug(str(ep.id) + ': ' + str(ep))
            # logger.debug(str(ep))

    def assert_finding_count(self, count, findings_content_json):
        self.assertEqual(findings_content_json['count'], count)

    def db_endpoint_count(self):
        return Endpoint.objects.all().count()

    def db_notes_count(self):
        return Notes.objects.all().count()

    # import zap scan, testing:
    # - import
    # - severity threshold
    # - active/verifed = True
    def import_zap_scan_original(self):
        logger.debug('importing original zap xml report')

        endpoint_count_before = self.db_endpoint_count()
        notes_count_before = self.db_notes_count()

        import1 = self.import_scan(
            {
                "scan_date": '2020-06-04',
                "minimum_severity": 'Low',  # skip the 1 information finding
                "active": True,
                "verified": True,
                "scan_type": 'ZAP Scan',
                "file": open(self.zap_sample1_filename),
                "engagement": 1,
                "version": "1.0.1",
            })

        test_id = import1['test']
        findings = self.get_test_findings(test_id)
        self.log_finding_summary(findings)

        # imported count must match count in xml report
        self.assert_finding_count(self.zap_sample1_count_above_threshold, findings)

        # the zap scan contains 2 new endpoints
        self.assertEqual(endpoint_count_before + 2, self.db_endpoint_count())

        # no notes expected
        self.assertEqual(notes_count_before, self.db_notes_count())

        return test_id

    # reimport zap scan, testing:
    # - reimport, findings stay the same, stay active
    # - severity threshold
    # - active = True
    # - verified = False (doesn't affect existing findings currently)
    def reimport_zap_scan_original(self, test_id):
        logger.debug('reimporting exact same original zap xml report again, verified=False')

        endpoint_count_before = self.db_endpoint_count()
        notes_count_before = self.db_notes_count()

        # reimport exact same report
        reimport1 = self.reimport_scan(
            {
                "test": test_id,
                "scan_date": '2020-06-04',
                "minimum_severity": 'Low',
                "active": True,
                "verified": False,
                "scan_type": 'ZAP Scan',
                "file": open(self.zap_sample1_filename),
                "engagement": 1,
                "version": "1.0.1",
            })

        test_id = reimport1['test']
        self.assertEqual(test_id, test_id)

        findings = self.get_test_findings(test_id)
        self.log_finding_summary(findings)

        # reimported count must match count in xml report
        # we set verified=False in this reimport, but currently DD does not update this flag, so it's still True from previous import
        findings = self.get_test_findings(test_id, verified=True)
        self.assert_finding_count(self.zap_sample1_count_above_threshold, findings)

        # inversely, we should see no findings with verified=False
        findings = self.get_test_findings(test_id, verified=False)
        self.assert_finding_count(0, findings)

        # reimporting the exact same scan shouldn't modify the number of endpoints
        self.assertEqual(endpoint_count_before, self.db_endpoint_count())

        # reimporting the exact same scan shouldn't create any notes
        self.assertEqual(notes_count_before, self.db_notes_count())

    def reimport_zap_scan_updated(self, test_id):
        logger.debug('reimporting updated zap xml report, 1 new finding and 1 no longer present, verified=True')

        endpoint_count_before = self.db_endpoint_count()
        notes_count_before = self.db_notes_count()

        # reimport updated report
        reimport1 = self.reimport_scan(
            {
                "test": test_id,
                "scan_date": '2020-06-04',
                "minimum_severity": 'Low',
                "active": True,
                "verified": True,
                "scan_type": 'ZAP Scan',
                "file": open(self.zap_sample2_filename),
                "engagement": 1,
                "version": "1.0.1",
            })

        test_id = reimport1['test']
        self.assertEqual(test_id, test_id)

        test = self.get_test(test_id)
        findings = self.get_test_findings(test_id)
        self.log_finding_summary(findings)

        # active findings must be equal to those in the report
        findings = self.get_test_findings(test_id, active=True, verified=True)
        self.assert_finding_count(self.zap_sample1_count_above_threshold, findings)

        # the updated scan report has 1 new endpoint + 1 new note of the mitigated finding
        self.assertEqual(endpoint_count_before + 1, self.db_endpoint_count())
        self.assertEqual(notes_count_before + 1, self.db_notes_count())

    # reimport original zap scan, after the updated scan has closed 1 finding
    # - reimport, reactivating 1 finding (and mitigating another)
    # - severity threshold
    # - active = True
    # - verified = False (doesn't affect existing findings currently)
    def reimport_zap_scan_original_after_updated_after_original(self, test_id):
        logger.debug('reimporting exact same original zap xml report again, verified=False')

        endpoint_count_before = self.db_endpoint_count()
        notes_count_before = self.db_notes_count()

        # reimport exact same report
        reimport1 = self.reimport_scan(
            {
                "test": test_id,
                "scan_date": '2020-06-04',
                "minimum_severity": 'Low',
                "active": True,
                "verified": False,
                "scan_type": 'ZAP Scan',
                "file": open(self.zap_sample1_filename),
                "engagement": 1,
                "version": "1.0.1",
            })

        test_id = reimport1['test']
        self.assertEqual(test_id, test_id)

        findings = self.get_test_findings(test_id)
        self.log_finding_summary(findings)
        self.assert_finding_count(4, findings)  # there are 4 unique findings, 2 are shared between the 2 reports, 1 is informational so below threshold

        # reimported count must match count in xml report
        # we set verified=False in this reimport, but currently DD does not update this flag, so it's still True from previous import
        findings = self.get_test_findings(test_id, verified=True)
        # print('logging summary1')
        self.log_finding_summary(findings)
        # print('asserting1')
        self.assert_finding_count(self.zap_sample1_count_above_threshold, findings)

        # 1 finding still remains from the original import as not verified, because the verified flag is not updated by DD when reactivating a finding.
        findings = self.get_test_findings(test_id, verified=False)
        # print('logging summary2')
        self.log_finding_summary(findings)
        # print('asserting2')
        self.assert_finding_count(1, findings)

        # the updated scan report has 1 new endpoint, but his has already been added in the previous step
        self.assertEqual(endpoint_count_before, self.db_endpoint_count())
        # previous step: note 1: 1 finding mitigated
        # this step note 2 and 3: finding reactivated + finding mitigated, so 2 new notes in this step
        self.assertEqual(notes_count_before + 2, self.db_notes_count())

    # test what happens if we import the same report, but with changed severities and an extra endpoint in the report and an extra endpoint parameter
    # currently defect dojo sees them as different (new) findings.
    # the reimport process does not use the hash code based deduplication (yet)
    # this probably something that should change, but at least we have now captured current behaviour in a test
    def reimport_zap_scan_updated_severity_and_new_endpoints(self, test_id):
        logger.debug('reimporting original zap xml report, but with changed severities')

        endpoint_count_before = self.db_endpoint_count()
        notes_count_before = self.db_notes_count()

        # reimport updated report
        reimport1 = self.reimport_scan(
            {
                "test": test_id,
                "scan_date": '2020-06-04',
                "minimum_severity": 'Low',
                "active": True,
                "verified": True,
                "scan_type": 'ZAP Scan',
                "file": open(self.zap_sample3_filename),
                "engagement": 1,
                "version": "1.0.1",
                "endpoint_to_add": 1,
            })

        test_id = reimport1['test']
        self.assertEqual(test_id, test_id)

        test = self.get_test(test_id)
        findings = self.get_test_findings(test_id)
        self.log_finding_summary(findings)

        # total findings must be equal to those in the report, 3 active, 3 mitigated
        findings = self.get_test_findings(test_id)
        self.assert_finding_count(self.zap_sample1_count_above_threshold + self.zap_sample3_count_above_threshold, findings)
        findings = self.get_test_findings(test_id, active=True)
        self.assert_finding_count(self.zap_sample3_count_above_threshold, findings)

        # check if the "endpoint_to_add" param worked
        for finding in findings['results']:
            self.assertTrue(1 in finding['endpoints'])

        findings = self.get_test_findings(test_id, active=False)
        self.assert_finding_count(self.zap_sample1_count_above_threshold, findings)

        # check if the "endpoint_to_add" param was NOT added to the previous existing findings
        for finding in findings['results']:
            self.assertFalse(1 in finding['endpoints'])

        # the updated scan report with changed severities also has 1 new endpoint
        self.assertEqual(endpoint_count_before + 1, self.db_endpoint_count())
        # 3 notes expected for the mitigated findings
        self.assertEqual(notes_count_before + 3, self.db_notes_count())

    def reimport_zap_scan_all_different_endpoints(self, test_id):
        logger.debug('reimporting original zap xml report, but with completely different endpoints severities')

        endpoint_count_before = self.db_endpoint_count()
        notes_count_before = self.db_notes_count()

        # reimport updated report
        reimport1 = self.reimport_scan(
            {
                "test": test_id,
                "scan_date": '2020-06-04',
                "minimum_severity": 'Low',
                "active": True,
                "verified": True,
                "scan_type": 'ZAP Scan',
                "file": open(self.zap_sample4_filename),
                "engagement": 1,
                "version": "1.0.1",
            })

        test_id = reimport1['test']
        self.assertEqual(test_id, test_id)

        test = self.get_test(test_id)
        findings = self.get_test_findings(test_id)
        self.log_finding_summary(findings)

        # no new findings expected as only the endpoints are different
        findings = self.get_test_findings(test_id)
        self.assert_finding_count(self.zap_sample4_count_above_threshold, findings)

        # the updated scan report has all endpoints changed. the previous endpoints are no longer present, but DD keeps them anyway.
        # so there should be 2 new endpoints. 1 for the mainhost in zap report and 1 for the uri used in each finding
        self.assertEqual(endpoint_count_before + 2, self.db_endpoint_count())
        # no new notes expected
        self.assertEqual(notes_count_before, self.db_notes_count())

    def test_import(self):
        test_id = self.import_zap_scan_original()

    def test_import_reimport_same(self):
        test_id = self.import_zap_scan_original()
        self.reimport_zap_scan_original(test_id)

    def test_import_reimport_different(self):
        test_id = self.import_zap_scan_original()
        self.reimport_zap_scan_updated(test_id)

    def test_import_reimport_different_multiple(self):
        test_id = self.import_zap_scan_original()
        self.reimport_zap_scan_updated(test_id)
        self.reimport_zap_scan_original_after_updated_after_original(test_id)

    def test_import_reimport_different_severity_and_new_endpoints(self):
        test_id = self.import_zap_scan_original()
        self.reimport_zap_scan_updated_severity_and_new_endpoints(test_id)

    def test_import_reimport_all_different_endpoints(self):
        test_id = self.import_zap_scan_original()
        self.reimport_zap_scan_all_different_endpoints(test_id)


# Observations:
# - When reopening a mititgated finding, almost no fields are updated such as title, description, severity, impact, references, ....
# - Basically fields (and req/resp) are only stored on the initial import, reimporting only changes the active/mitigated/verified flags + some dates + notes
# - (Re)Import could provide some more statistics of imported findings (reimport: new, mitigated, reactivated, untouched, ...)
# - Endpoints that are no longer present in the scan that is imported, are still retained by DD, which makes them look "active" in the product view
