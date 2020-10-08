from django.test import TestCase
from dojo.models import Finding, User, Product, Endpoint, Endpoint_Status, Test
from dojo.models import System_Settings
from crum import impersonate
import logging
logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")

loglevel = logging.DEBUG
logging.basicConfig(level=loglevel)

# WIP


class TestDuplicationLogic(TestCase):
    fixtures = ['dojo_testdata.json']

    def run(self, result=None):
        testuser = User.objects.get(username='admin')
        testuser.usercontactinfo.block_execution = True
        testuser.save()

        # unit tests are running without any user, which will result in actions like dedupe happening in the celery process
        # this doesn't work in unittests as unittests are using an in memory sqlite database and celery can't see the data
        # so we're running the test under the admin user context and set block_execution to True
        with impersonate(testuser):
            super().run(result)

    def setUp(self):
        logger.debug('enabling deduplication')
        system_settings = System_Settings.objects.get()
        system_settings.enable_deduplication = True
        system_settings.save()
        self.log_summary(product=2)

    def tearDown(self):
        self.log_summary(test=33)
        # self.log_summary(product=2)

    # findings 23, 24, 25 in test 33 are scan_Type Generic Findings Import which uses the legacy algo
    def test_identical_legacy(self):
        # 24 is already a duplicate of 22 let's see what happens if we create an identical finding (but reset status)
        # expect: marked as duplicate
        finding_new, finding_24 = self.copy_and_reset_finding(id=24)
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=4, duplicate=True, duplicate_finding_id=finding_24.duplicate_finding.id, hash_code=finding_24.hash_code)

    def test_identical_except_title_legacy(self):
        # 24 is already a duplicate of 22, let's see what happens if we create an identical finding with different title (and reset status)
        # expect: NOT marked as duplicate as title is part of hash_code calculation
        finding_new, finding_4 = self.copy_and_reset_finding(id=4)
        finding_new.title = 'the best title'
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=4, duplicate=False, not_hash_code=finding_4.hash_code)
        return

    def test_identical_except_description_legacy(self):
        # 24 is already a duplicate of 22, let's see what happens if we create an identical finding with different description (and reset status)
        # expect: marked as duplicate
        finding_new, finding_24 = self.copy_and_reset_finding(id=4)
        finding_new.description = 'useless finding'
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=4, duplicate=True, duplicate_finding_id=finding_24.duplicate_finding.id, hash_code=finding_24.hash_code)
        return

    def test_identical_except_line_legacy(self):
        # 24 is already a duplicate of 22, let's see what happens if we create an identical finding with different line (and reset status)
        # expect: not marked as duplicate
        finding_new, finding_24 = self.copy_and_reset_finding(id=24)
        finding_new.line = 666
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=4, duplicate=False, not_hash_code=finding_24.hash_code)
        return

    def test_identical_except_filepath_legacy(self):
        # 24 is already a duplicate of 22, let's see what happens if we create an identical finding with different file_path (and reset status)
        # expect: not marked as duplicate
        finding_new, finding_24 = self.copy_and_reset_finding(id=24)
        finding_new.file_path = '/dev/null'

        finding_22 = Finding.objects.get(id=22)
        logger.debug('finding_new.file_path: %s', finding_new.file_path)
        logger.debug('finding_new.line: %i', finding_new.line)
        logger.debug('finding_22.file_path: %s', finding_22.file_path)
        logger.debug('finding_22.line: %i', finding_22.line)

        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=24, duplicate=False, not_hash_code=finding_24.hash_code)
        return

    # def test_identical_except_endpoints_legacy(self):
    #     return

    # existing findings in test 3 are from ZAP scanner, which uses hash_code algorithm with ['title', 'cwe', 'endpoints', 'severity']

    def test_identical_hash_code(self):
        # 4 is already a duplicate of 2, let's see what happens if we create an identical finding (but reset status)
        # expect: marked as duplicate
        finding_new, finding_4 = self.copy_and_reset_finding(id=4)
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=4, duplicate=True, duplicate_finding_id=finding_4.duplicate_finding.id, hash_code=finding_4.hash_code)
        return

    def test_identical_except_title_hash_code(self):
        # 4 is already a duplicate of 2, let's see what happens if we create an identical finding with different title (and reset status)
        # expect: NOT marked as duplicate as title is part of hash_code calculation
        finding_new, finding_4 = self.copy_and_reset_finding(id=4)
        finding_new.title = 'the best title'
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=4, duplicate=False, not_hash_code=finding_4.hash_code)
        return

    def test_identical_except_description_legacy_hash_code(self):
        # 4 is already a duplicate of 2, let's see what happens if we create an identical finding with different description (and reset status)
        # expect: marked as duplicate
        finding_new, finding_4 = self.copy_and_reset_finding(id=4)
        finding_new.description = 'useless finding'
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=4, duplicate=True, duplicate_finding_id=finding_4.duplicate_finding.id, hash_code=finding_4.hash_code)
        return

    # TODO not usefile with ZAP?
    def test_identical_except_line_hash_code(self):
        # 4 is already a duplicate of 2, let's see what happens if we create an identical finding with different line (and reset status)
        # expect: marked as duplicate
        finding_new, finding_4 = self.copy_and_reset_finding(id=4)
        finding_new.line = 666
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=4, duplicate=True, duplicate_finding_id=finding_4.duplicate_finding.id, hash_code=finding_4.hash_code)
        return

    # TODO not usefile with ZAP?
    def test_identical_except_filepath_hash_code(self):
        # 4 is already a duplicate of 2, let's see what happens if we create an identical finding with different file_path (and reset status)
        # expect: marked as duplicate
        finding_new, finding_4 = self.copy_and_reset_finding(id=4)
        finding_new.file_path = '/dev/null'
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=4, duplicate=True, duplicate_finding_id=finding_4.duplicate_finding.id, hash_code=finding_4.hash_code)
        return

    # def test_identical_except_endpoints_legacy_hash_code(self):
    #     return

    # TODO endpoint tests

    # def test_identical_unique_id(self):
    #     return

    # def test_identical_except_title_unique_id(self):
    #     return

    # def test_identical_except_description_unique_id(self):
    #     return

    # def test_identical_except_line_unique_id(self):
    #     return

    # def test_identical_except_filepath_unique_id(self):
    #     return

    # def test_identical_except_endpoints_unique_id(self):
    #     return

    # def test_identical_unique_id_or_hash_code(self):
    #     return

    # def test_identical_except_title_unique_id_or_hash_code(self):
    #     return

    # def test_identical_except_description_unique_id_or_hash_code(self):
    #     return

    # def test_identical_except_line_unique_id_or_hash_code(self):
    #     return

    # def test_identical_except_filepath_unique_id_or_hash_code(self):
    #     return

    # def test_identical_except_endpoints_unique_id_or_hash_code(self):
    #     return

    # def test_multiple_identical_dedupe_ordering(self):
    #     return

    def log_product(self, product):
        if isinstance(product, int):
            product = Product.objects.get(pk=product)

        logger.debug('product %i: %s', product.id, product.name)
        for eng in product.engagement_set.all():
            self.log_engagement(eng)
            for test in eng.test_set.all():
                self.log_test(test)

    def log_engagement(self, eng):
        if isinstance(eng, int):
            eng = Engagement.objects.get(pk=eng)

        logger.debug('engagement %i: %s', eng.id, eng.name)

    def log_test(self, test):
        if isinstance(test, int):
            test = Test.objects.get(pk=test)

        logger.debug('test %i: %s (algo=%s)', test.id, test, test.dedupe_algo)
        self.log_findings(test.finding_set.all())

    def log_all_products(self):
        for product in Product.objects.all():
            self.log_summary(product=product)

    def log_findings(self, findings):
        if not findings:
            logger.debug('no findings')
        else:
            for finding in findings:
                logger.debug('{:4.4}'.format(str(finding.id)) + ': "' + '{:20.20}'.format(finding.title) + '": ' + '{:5.5}'.format(finding.severity) + ': act: ' + '{:5.5}'.format(str(finding.active)) +
                        ': ver: ' + '{:5.5}'.format(str(finding.verified)) + ': mit: ' + '{:5.5}'.format(str(finding.is_Mitigated)) +
                        ': dup: ' + '{:5.5}'.format(str(finding.duplicate)) + ': dup_id: ' +
                        ('{:4.4}'.format(str(finding.duplicate_finding.id)) if finding.duplicate_finding else 'None') + ': hash_code: ' + finding.hash_code +
                        ': eps: ' + str(finding.endpoints.count()) + ": notes: " + str([n.id for n in finding.notes.all()]))

        logger.debug('endpoints')
        for ep in Endpoint.objects.all():
            logger.debug(str(ep.id) + ': ' + str(ep))

        logger.debug('endpoint statuses')
        for eps in Endpoint_Status.objects.all():
            logger.debug(str(eps.id) + ': ' + str(eps))

    def log_summary(self, product=None, engagement=None, test=None):
        if product:
            self.log_product(product)

        if engagement:
            self.log_engagement(engagement)

        if test:
            self.log_test(test)

        if not product and not engagement and not test:
            self.log_all_products()

    def copy_and_reset_finding(self, id=None):
        finding_org = Finding.objects.get(id=id)
        finding_new = finding_org
        finding_new.pk = None
        finding_new.duplicate = False
        finding_new.duplicate_finding = None
        finding_new.active = True
        finding_new.hash_code = None
        # return unsaved new finding and reloaded existing finding
        return finding_new, Finding.objects.get(id=id)

    def assert_finding(self, finding, not_pk=None, duplicate=False, duplicate_finding_id=None, hash_code=None, not_hash_code=None):
        if not_pk:
            self.assertNotEqual(finding.pk, not_pk)

        self.assertEqual(finding.duplicate, duplicate)
        if not duplicate:
            self.assertFalse(finding.duplicate_finding)  # False -> None

        if duplicate_finding_id:
            self.assertTrue(finding.duplicate_finding)  # True -> not None
            self.assertEqual(finding.duplicate_finding.id, duplicate_finding_id)

        if hash_code:
            self.assertEqual(finding.hash_code, hash_code)

        if not_hash_code:
            self.assertNotEqual(finding.hash_code, hash_code)


# TODO check endpoints
# TODO check endpoint_statuses
# TODO identical but different endpoints
# TODO dedupe_inside_engagement
# TODO add legacy case without endpoints without filepath without -> no dedupe happening!
