from rest_framework.test import APITestCase, APIClient
from django.urls import reverse
from dojo.models import Finding, Test, Test_Type
from rest_framework.authtoken.models import Token
from django.core.files.uploadedfile import SimpleUploadedFile


class ScanImportOptionsTest(APITestCase):
    """
    Test the options `skip_duplicates` and `close_old_findings` for the scan
    import APIv2 endpoint.
    """
    fixtures = ['dojo_testdata.json']
    EMPTY_ZAP_SCAN = """<?xml version="1.0"?>
<OWASPZAPReport version="2.7.0" generated="Tue, 17 Apr 2018 07:18:05">
</OWASPZAPReport>
"""

    def setUp(self):
        token = Token.objects.get(user__username='admin')
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
        self._first_import_test = self.import_zap_scan()
        test = self.import_zap_scan()
        test.test_type = Test_Type.objects.create(name='some other test tool')
        test.save()

    def import_zap_scan(self, skip_duplicates=False, close_old_findings=False, upload_empty_scan=False):
        if upload_empty_scan:
            file = SimpleUploadedFile("zap_sample.xml",
                                      self.EMPTY_ZAP_SCAN,
                                      content_type='text/xml')
        else:
            file = open('tests/zap_sample.xml')
        payload = {
            'engagement': 1,
            'scan_type': 'ZAP Scan',
            'skip_duplicates': skip_duplicates,
            'close_old_findings': close_old_findings,
            'file': file,
        }
        test_ids = list(Test.objects.values_list('id', flat=True))
        r = self.client.post(reverse('importscan-list'), payload)
        self.assertEqual(201, r.status_code)
        return Test.objects.exclude(id__in=test_ids).get()

    def get_all_finding_ids(self, **kwargs):
        return set(Finding.objects.filter(test__engagement_id=1, **kwargs)
                   .order_by('id').values_list('id', flat=True))

    def test_duplicates_skipped(self):
        """
        Check that no duplicate finding will be imported when `skip_duplicates` is set.
        """
        test = self.import_zap_scan(skip_duplicates=True)
        self.assertFalse(test.finding_set.exists())

    def test_duplicates_not_skipped(self):
        """
        Check that all findings will be imported when `skip_duplicates` is not set.
        """
        test = self.import_zap_scan(skip_duplicates=False)
        self.assertEqual(
            set(self._first_import_test.finding_set.values_list('hash_code', flat=True)),
            set(test.finding_set.values_list('hash_code', flat=True)),
        )

    def test_only_closed_iff_not_duplicate(self):
        """
        Check that duplicates are not closed and that non-duplicates are closed
        when `close_old_findings` is set (and `skip_duplicates` is not.)
        """

        previously_active_finding_ids = self.get_all_finding_ids(active=True)
        test = self.import_zap_scan(close_old_findings=True)
        self.assertFalse(Finding.objects
                         .filter(hash_code__in=test.finding_set.values('hash_code'),
                                 id__in=previously_active_finding_ids,
                                 active=False).exists())
        self.assertFalse(Finding.objects
                         .exclude(hash_code__in=test.finding_set.values('hash_code'))
                         .filter(active=True).exists())

    def test_old_findings_closed(self):
        """
        Check that old findings are closed when `close_old_findings` is set.
        """
        test = self.import_zap_scan(close_old_findings=True, upload_empty_scan=True)
        self.assertFalse(self.get_all_finding_ids(active=True, test__test_type=test.test_type))

    def test_old_findings_not_closed(self):
        """
        Check that old findings are not closed when `close_old_findings` is not set.
        """
        previously_active_finding_ids = self.get_all_finding_ids(active=True)
        self.import_zap_scan(close_old_findings=False, upload_empty_scan=True)
        self.assertEqual(previously_active_finding_ids,
                         self.get_all_finding_ids(active=True))

    def test_originals_of_skipped_duplicates_are_not_closed(self):
        """
        Check that `skip_duplicates` and `close_old_findings` are compatible by
        verifying that all duplicates are skipped and a finding is closed iff
        it is not the original of a skipped duplicate when `skip_duplicates`
        and close_old_findings` are set.
        """
        test = self.import_zap_scan(skip_duplicates=True, close_old_findings=True)
        self.assertFalse(test.finding_set.exists())
        self.assertEqual(
            self.get_all_finding_ids(test=self._first_import_test),
            self.get_all_finding_ids(active=True, test__test_type=test.test_type),
        )
