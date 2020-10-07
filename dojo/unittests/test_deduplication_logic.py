from django.test import TestCase
from dojo.utils import set_duplicate
from dojo.models import Finding, User, Product, Endpoint, Endpoint_Status
from dojo.models import System_Settings
import logging
logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")

loglevel = logging.DEBUG
logging.basicConfig(level=loglevel)

# WIP


class TestDuplicationLogic(TestCase):
    fixtures = ['dojo_testdata.json']

    def setUp(self):
        logger.debug('enabling deduplication')
        system_settings = System_Settings.objects.get()
        system_settings.enable_deduplication = True
        system_settings.save()
        self.finding_a = Finding.objects.get(id=2)
        self.finding_a.pk = None
        self.finding_a.duplicate = False
        self.finding_a.duplicate_finding = None
        self.finding_a.save(dedupe_option=True)
        self.finding_b = Finding.objects.get(id=3)
        self.finding_b.pk = None
        self.finding_b.duplicate = False
        self.finding_b.duplicate_finding = None
        self.finding_b.save()
        self.finding_c = Finding.objects.get(id=4)
        self.finding_c.duplicate = False
        self.finding_c.duplicate_finding = None
        self.finding_c.pk = None
        self.finding_c.save()

    def tearDown(self):
        if self.finding_a.id:
            self.finding_a.delete()
        if self.finding_b.id:
            self.finding_b.delete()
        if self.finding_c.id:
            self.finding_c.delete()

    # Set A as duplicate of B and check both directions
    def test_set_duplicate_basic(self):
        testuser = User.objects.get(username='admin')
        testuser.usercontactinfo.block_execution = True
        testuser.save()

        from dojo.utils import get_current_user
        from crum import impersonate
        with impersonate(testuser):
            user = get_current_user()
            logger.debug('unittests getting current user: %s', user)

            self.log_summary()

            logger.debug('enabling deduplication2')
            system_settings = System_Settings.objects.get()
            system_settings.enable_deduplication = True
            system_settings.save()
            system_settings = System_Settings.objects.get()
            logger.debug('all: ' + str(Finding.objects.all().count()))
            logger.debug('enable_deduplication: %s', system_settings.enable_deduplication)
            self.finding_a.title = "valentijn"
            self.finding_a.save()
            set_duplicate(self.finding_a, self.finding_b)

        self.assertTrue(self.finding_a.duplicate)
        self.assertFalse(self.finding_b.duplicate)
        self.assertEqual(self.finding_a.duplicate_finding.id, self.finding_b.id)
        self.assertEqual(self.finding_b.duplicate_finding, None)
        self.assertEqual(self.finding_b.original_finding.first().id, self.finding_a.id)
        self.assertEqual(self.finding_a.duplicate_finding_set().count(), 1)
        self.assertEqual(self.finding_b.duplicate_finding_set().count(), 1)
        self.assertEqual(self.finding_b.duplicate_finding_set().first().id, self.finding_a.id)

    def test_identical_legacy(self):
        return

    def test_identical_except_title_legacy(self):
        return

    def test_identical_except_description_legacy(self):
        return

    def test_identical_except_line_legacy(self):
        return

    def test_identical_except_filepath_legacy(self):
        return

    def test_identical_except_endpoints_legacy(self):
        return

    def test_identical_hash_code(self):
        return

    def test_identical_except_title_hash_code(self):
        return

    def test_identical_except_description_legacy_hash_code(self):
        return

    def test_identical_except_line_hash_code(self):
        return

    def test_identical_except_filepath_hash_code(self):
        return

    def test_identical_except_endpoints_legacy_hash_code(self):
        return

    def test_identical_unique_id(self):
        return

    def test_identical_except_title_unique_id(self):
        return

    def test_identical_except_description_unique_id(self):
        return

    def test_identical_except_line_unique_id(self):
        return

    def test_identical_except_filepath_unique_id(self):
        return

    def test_identical_except_endpoints_unique_id(self):
        return

    def test_identical_unique_id_or_hash_code(self):
        return

    def test_identical_except_title_unique_id_or_hash_code(self):
        return

    def test_identical_except_description_unique_id_or_hash_code(self):
        return

    def test_identical_except_line_unique_id_or_hash_code(self):
        return

    def test_identical_except_filepath_unique_id_or_hash_code(self):
        return

    def test_identical_except_endpoints_unique_id_or_hash_code(self):
        return

    def test_multiple_identical_dedupe_ordering(self):
        return

    # # A duplicate should not be considered to be an original for another finding
    # def test_set_duplicate_exception_1(self):
    #     self.finding_a.duplicate = True
    #     self.finding_a.save()
    #     with self.assertRaisesRegex(Exception, "Existing finding is a duplicate"):
    #         set_duplicate(self.finding_b, self.finding_a)

    # # A finding should never be the duplicate of itself
    # def test_set_duplicate_exception_2(self):
    #     with self.assertRaisesRegex(Exception, "Can not add duplicate to itself"):
    #         set_duplicate(self.finding_b, self.finding_b)

    # # Two duplicate findings can not be duplicates of each other as well
    # def test_set_duplicate_exception_3(self):
    #     set_duplicate(self.finding_a, self.finding_b)
    #     set_duplicate(self.finding_c, self.finding_b)
    #     with self.assertRaisesRegex(Exception, "Existing finding is a duplicate"):
    #         set_duplicate(self.finding_a, self.finding_c)

    # # Merge duplicates: If the original of a dupicate is now considered to be a duplicate of a new original the old duplicate should be appended too
    # def test_set_duplicate_exception_merge(self):
    #     set_duplicate(self.finding_a, self.finding_b)
    #     set_duplicate(self.finding_b, self.finding_c)

    #     self.finding_a = Finding.objects.get(id=self.finding_a.id)
    #     self.assertTrue(self.finding_b.duplicate)
    #     self.assertTrue(self.finding_a.duplicate)
    #     self.assertFalse(self.finding_c.duplicate)
    #     self.assertEqual(self.finding_b.duplicate_finding.id, self.finding_c.id)
    #     self.assertEqual(self.finding_a.duplicate_finding.id, self.finding_c.id)
    #     self.assertEqual(self.finding_c.duplicate_finding, None)
    #     self.assertEqual(self.finding_a.duplicate_finding_set().count(), 2)
    #     self.assertEqual(self.finding_b.duplicate_finding_set().count(), 2)
    #     self.assertEqual(self.finding_a.duplicate_finding.id, self.finding_c.id)

    # # if a duplicate is deleted the original should still be present
    # def test_set_duplicate_exception_delete_1(self):
    #     set_duplicate(self.finding_a, self.finding_b)
    #     self.assertEqual(self.finding_b.original_finding.first().id, self.finding_a.id)
    #     self.finding_a.delete()
    #     self.assertEqual(self.finding_a.id, None)
    #     self.assertEqual(self.finding_b.original_finding.first(), None)

    # # if the original is deleted all duplicates should be deleted
    # def test_set_duplicate_exception_delete_2(self):
    #     set_duplicate(self.finding_a, self.finding_b)
    #     self.assertEqual(self.finding_b.original_finding.first().id, self.finding_a.id)
    #     self.finding_b.delete()
    #     with self.assertRaises(Finding.DoesNotExist):
    #         self.finding_a = Finding.objects.get(id=self.finding_a.id)
    #     self.assertEqual(self.finding_b.id, None)

    # def test_loop_relations_for_one(self):
    #     self.finding_b.duplicate = True
    #     self.finding_b.duplicate_finding = self.finding_b
    #     super(Finding, self.finding_b).save()
    #     candidates = Finding.objects.filter(duplicate_finding__isnull=False, original_finding__isnull=False).count()
    #     self.assertEqual(candidates, 1)
    #     fix_loop_duplicates()
    #     candidates = Finding.objects.filter(duplicate_finding__isnull=False, original_finding__isnull=False).count()
    #     self.assertEqual(candidates, 0)

    # # if two findings are connected with each other the fix_loop function should detect and remove the loop
    # def test_loop_relations_for_two(self):

    #     set_duplicate(self.finding_a, self.finding_b)
    #     self.finding_b.duplicate = True
    #     self.finding_b.duplicate_finding = self.finding_a

    #     super(Finding, self.finding_a).save()
    #     super(Finding, self.finding_b).save()

    #     fix_loop_duplicates()

    #     candidates = Finding.objects.filter(duplicate_finding__isnull=False, original_finding__isnull=False).count()
    #     self.assertEqual(candidates, 0)

    #     # Get latest status
    #     self.finding_a = Finding.objects.get(id=self.finding_a.id)
    #     self.finding_b = Finding.objects.get(id=self.finding_b.id)

    #     if self.finding_a.duplicate_finding:
    #         self.assertTrue(self.finding_a.duplicate)
    #         self.assertEqual(self.finding_a.original_finding.count(), 0)
    #     else:
    #         self.assertFalse(self.finding_a.duplicate)
    #         self.assertEqual(self.finding_a.original_finding.count(), 1)

    #     if self.finding_b.duplicate_finding:
    #         self.assertTrue(self.finding_b.duplicate)
    #         self.assertEqual(self.finding_b.original_finding.count(), 0)
    #     else:
    #         self.assertFalse(self.finding_b.duplicate)
    #         self.assertEqual(self.finding_b.original_finding.count(), 1)

    # # Similar Loop detection and deletion for three findings
    # def test_loop_relations_for_three(self):

    #     set_duplicate(self.finding_a, self.finding_b)
    #     self.finding_b.duplicate = True
    #     self.finding_b.duplicate_finding = self.finding_c
    #     self.finding_c.duplicate = True
    #     self.finding_c.duplicate_finding = self.finding_a

    #     super(Finding, self.finding_a).save()
    #     super(Finding, self.finding_b).save()
    #     super(Finding, self.finding_c).save()

    #     fix_loop_duplicates()

    #     # Get latest status
    #     self.finding_a = Finding.objects.get(id=self.finding_a.id)
    #     self.finding_b = Finding.objects.get(id=self.finding_b.id)
    #     self.finding_c = Finding.objects.get(id=self.finding_c.id)

    #     if self.finding_a.duplicate_finding:
    #         self.assertTrue(self.finding_a.duplicate)
    #         self.assertEqual(self.finding_a.original_finding.count(), 0)
    #     else:
    #         self.assertFalse(self.finding_a.duplicate)
    #         self.assertEqual(self.finding_a.original_finding.count(), 2)

    #     if self.finding_b.duplicate_finding:
    #         self.assertTrue(self.finding_b.duplicate)
    #         self.assertEqual(self.finding_b.original_finding.count(), 0)
    #     else:
    #         self.assertFalse(self.finding_b.duplicate)
    #         self.assertEqual(self.finding_b.original_finding.count(), 2)

    #     if self.finding_c.duplicate_finding:
    #         self.assertTrue(self.finding_c.duplicate)
    #         self.assertEqual(self.finding_c.original_finding.count(), 0)
    #     else:
    #         self.assertFalse(self.finding_c.duplicate)
    #         self.assertEqual(self.finding_c.original_finding.count(), 2)

    # # Another loop-test for 4 findings
    # def test_loop_relations_for_four(self):
    #     self.finding_d = Finding.objects.get(id=4)
    #     self.finding_d.pk = None
    #     self.finding_d.duplicate = False
    #     self.finding_d.duplicate_finding = None
    #     self.finding_d.save()

    #     set_duplicate(self.finding_a, self.finding_b)
    #     self.finding_b.duplicate = True
    #     self.finding_b.duplicate_finding = self.finding_c
    #     self.finding_c.duplicate = True
    #     self.finding_c.duplicate_finding = self.finding_d
    #     self.finding_d.duplicate = True
    #     self.finding_d.duplicate_finding = self.finding_a

    #     super(Finding, self.finding_a).save()
    #     super(Finding, self.finding_b).save()
    #     super(Finding, self.finding_c).save()
    #     super(Finding, self.finding_d).save()

    #     fix_loop_duplicates()

    #     # Get latest status
    #     self.finding_a = Finding.objects.get(id=self.finding_a.id)
    #     self.finding_b = Finding.objects.get(id=self.finding_b.id)
    #     self.finding_c = Finding.objects.get(id=self.finding_c.id)
    #     self.finding_d = Finding.objects.get(id=self.finding_d.id)

    #     if self.finding_a.duplicate_finding:
    #         self.assertTrue(self.finding_a.duplicate)
    #         self.assertEqual(self.finding_a.original_finding.count(), 0)
    #     else:
    #         self.assertFalse(self.finding_a.duplicate)
    #         self.assertEqual(self.finding_a.original_finding.count(), 3)

    #     if self.finding_b.duplicate_finding:
    #         self.assertTrue(self.finding_b.duplicate)
    #         self.assertEqual(self.finding_b.original_finding.count(), 0)
    #     else:
    #         self.assertFalse(self.finding_b.duplicate)
    #         self.assertEqual(self.finding_b.original_finding.count(), 3)

    #     if self.finding_c.duplicate_finding:
    #         self.assertTrue(self.finding_c.duplicate)
    #         self.assertEqual(self.finding_c.original_finding.count(), 0)
    #     else:
    #         self.assertFalse(self.finding_c.duplicate)
    #         self.assertEqual(self.finding_c.original_finding.count(), 3)

    #     if self.finding_d.duplicate_finding:
    #         self.assertTrue(self.finding_d.duplicate)
    #         self.assertEqual(self.finding_d.original_finding.count(), 0)
    #     else:
    #         self.assertFalse(self.finding_d.duplicate)
    #         self.assertEqual(self.finding_d.original_finding.count(), 3)

    # # Similar Loop detection and deletion for three findings
    # def test_list_relations_for_three(self):

    #     set_duplicate(self.finding_a, self.finding_b)
    #     self.finding_b.duplicate = True
    #     self.finding_b.duplicate_finding = self.finding_c

    #     super(Finding, self.finding_a).save()
    #     super(Finding, self.finding_b).save()
    #     super(Finding, self.finding_c).save()

    #     fix_loop_duplicates()

    #     self.finding_a = Finding.objects.get(id=self.finding_a.id)
    #     self.finding_b = Finding.objects.get(id=self.finding_b.id)
    #     self.finding_c = Finding.objects.get(id=self.finding_c.id)

    #     self.assertTrue(self.finding_b.duplicate)
    #     self.assertTrue(self.finding_a.duplicate)
    #     self.assertFalse(self.finding_c.duplicate)
    #     self.assertEqual(self.finding_b.duplicate_finding.id, self.finding_c.id)
    #     self.assertEqual(self.finding_a.duplicate_finding.id, self.finding_c.id)
    #     self.assertEqual(self.finding_c.duplicate_finding, None)
    #     self.assertEqual(self.finding_a.duplicate_finding_set().count(), 2)
    #     self.assertEqual(self.finding_b.duplicate_finding_set().count(), 2)

    # def test_list_relations_for_three_reverse(self):
    #     set_duplicate(self.finding_c, self.finding_b)
    #     self.finding_b.duplicate = True
    #     self.finding_b.duplicate_finding = self.finding_a

    #     super(Finding, self.finding_a).save()
    #     super(Finding, self.finding_b).save()
    #     super(Finding, self.finding_c).save()

    #     fix_loop_duplicates()

    #     self.finding_a = Finding.objects.get(id=self.finding_a.id)
    #     self.finding_b = Finding.objects.get(id=self.finding_b.id)
    #     self.finding_c = Finding.objects.get(id=self.finding_c.id)

    #     self.assertTrue(self.finding_b.duplicate)
    #     self.assertTrue(self.finding_c.duplicate)
    #     self.assertFalse(self.finding_a.duplicate)
    #     self.assertEqual(self.finding_b.duplicate_finding.id, self.finding_a.id)
    #     self.assertEqual(self.finding_c.duplicate_finding.id, self.finding_a.id)
    #     self.assertEqual(self.finding_a.duplicate_finding, None)
    #     self.assertEqual(self.finding_c.duplicate_finding_set().count(), 2)
    #     self.assertEqual(self.finding_b.duplicate_finding_set().count(), 2)

    def log_product(self, product):
        logger.debug('product %i: %s', product.id, product.name)
        for eng in product.engagement_set.all():
            self.log_engagement(eng)
            for test in eng.test_set.all():
                self.log_test(test)

    def log_engagement(self, eng):
        logger.debug('engagment %i: %s', eng.id, eng.name)

    def log_test(self, test):
        logger.debug('test %i: %s', test.id, test)
        self.log_findings(test.finding_set.all())

    def log_all_products(self):
        for product in Product.objects.all():
            self.log_summary(product=product)

    def log_findings(self, findings):
        if not findings:
            logger.debug('no findings')
        else:
            for finding in findings:
                logger.debug(str(finding.id) + ': "' + finding.title[:25] + '": ' + finding.severity + ': active: ' + str(finding.active) + ': verified: ' + str(finding.verified) +
                        ': is_Mitigated: ' + str(finding.is_Mitigated) + ": notes: " + str([n.id for n in finding.notes.all()]) +
                        ': duplicate: ' + str(finding.duplicate) + ': duplicate_finding: ' + (str(finding.duplicate_finding.id) if finding.duplicate_finding else 'None') +
                        ': endpoints: ' + str(finding.endpoints.count()) + ' : hash_code' + finding.hash_code)

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
