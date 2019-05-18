from rest_framework.test import APITestCase, APIClient
from django.core.urlresolvers import reverse
from dojo.models import Finding, Test, Test_Type
from rest_framework.authtoken.models import Token
from django.core.files.uploadedfile import SimpleUploadedFile
import time


class ScanImportOptionsCheckmarxTest(APITestCase):
    """
    Test the deduplication for the scan import APIv2 endpoint.
    """
    fixtures = ['dojo_testdata.json']

    def setUp(self):
        token = Token.objects.get(user__username='admin')
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
        print("Before first setup import:")
        print(self.get_all_finding_ids())

        # checkmarx import
#        self._first_import_test_checkmarx = self.import_checkmarx_scan()
#        print("After first setup import:")
#        print(self.get_all_finding_ids())
#        print(self._first_import_test_checkmarx.finding_set.values_list('hash_code', flat=True))
#        print("findings in first checkmarx import test:")
#        print(self.get_all_finding_ids(test=self._first_import_test_checkmarx))

        # ZAP import
        self._first_import_test_ZAP = self.import_zap_scan()
        print("After setup import:")
        print(self.get_all_finding_ids())

    def import_zap_scan(self, skip_duplicates=False, close_old_findings=False, upload_empty_scan=False):
        if upload_empty_scan:
            file = SimpleUploadedFile("zap_sample.xml",
                                      self.EMPTY_ZAP_SCAN,
                                      content_type='text/xml')
        else:
            file = open('tests/zap_sample_1vuln.xml')
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

    def import_checkmarx_scan(self, skip_duplicates=False, close_old_findings=False, upload_empty_scan=False):
        file = open('tests/checkmarx_single_finding.xml')
        payload = {
            'engagement': 1,
            'scan_type': 'Checkmarx Scan',
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

#    def test_duplicate_is_detected_checkmarx(self):
#        """
#        Check that duplicates are detected as such
#        with default skip_duplicates/close_old_findings configuration (both false)
#        """
#        test = self.import_checkmarx_scan(skip_duplicates=False)
#        #self.assertEqual(
#        #    set(self._first_import_test_checkmarx.finding_set.values_list('hash_code', flat=True)),
#        #    set(test.finding_set.values_list('hash_code', flat=True)),
#        #)
#        #print("self.get_all_finding_ids(active=True, test__test_type=self._first_import_test_checkmarx.test_type)");
#        #print(self.get_all_finding_ids(active=True, test__test_type=self._first_import_test_checkmarx.test_type))
#        #print("self.get_all_finding_ids(duplicate=True, test__test_type=self._first_import_test_checkmarx.test_type)");
#        #print(self.get_all_finding_ids(duplicate=True, test__test_type=self._first_import_test_checkmarx.test_type))
#        print("findings in new import:")
#        print(self.get_all_finding_ids(test=test))
#        print("active finding in new import:")
#        print(self.get_all_finding_ids(active=True, test=test))
#        print("duplicate finding in new import:")
#        print(self.get_all_finding_ids(duplicate=True, test=test))

#        self.assertEqual(
#            self.get_all_finding_ids(active=True, test__test_type=self._first_import_test_checkmarx.test_type),
#            self.get_all_finding_ids(duplicate=True, test__test_type=self._first_import_test_checkmarx.test_type)
#        )

    def test_duplicate_is_detected_zap(self):
        """
        Check that duplicates are detected as such
        with default skip_duplicates/close_old_findings configuration (both false)
        """
        test = self.import_zap_scan()
        print("findings in new import:")
        print(self.get_all_finding_ids(test=test))
        print("active finding in new import:")
        print(self.get_all_finding_ids(active=True, test=test))
        print("duplicate finding in new import:")
        print(self.get_all_finding_ids(duplicate=True, test=test))
        time.sleep(60)
        print("active finding in new import after 1mn:")
        print(self.get_all_finding_ids(active=True, test=test))
        print("duplicate finding in new import after 1mn:")
        print(self.get_all_finding_ids(duplicate=True, test=test))

        # Check that all new findings are duplicate
        self.assertEqual(
            self.get_all_finding_ids(test=test),
            self.get_all_finding_ids(duplicate=True, test=test)
        )
