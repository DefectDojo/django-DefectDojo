from crum import impersonate
from django.test.utils import override_settings
from .dojo_test_case import DojoTestCase
from dojo.utils import set_duplicate
from dojo.management.commands.fix_loop_duplicates import fix_loop_duplicates
from dojo.models import Engagement, Finding, Product, User
import logging


logger = logging.getLogger(__name__)


class TestDuplicationLoops(DojoTestCase):
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
        self.finding_a = Finding.objects.get(id=2)
        self.finding_a.pk = None
        self.finding_a.title = 'A: ' + self.finding_a.title
        self.finding_a.duplicate = False
        self.finding_a.duplicate_finding = None
        self.finding_a.hash_code = None
        self.finding_a.save()
        self.finding_b = Finding.objects.get(id=3)
        self.finding_b.pk = None
        self.finding_b.title = 'B: ' + self.finding_b.title
        self.finding_b.duplicate = False
        self.finding_b.duplicate_finding = None
        self.finding_b.hash_code = None
        self.finding_b.save()
        self.finding_c = Finding.objects.get(id=4)
        self.finding_c.pk = None
        self.finding_c.title = 'C: ' + self.finding_c.title
        self.finding_c.duplicate = False
        self.finding_c.duplicate_finding = None
        self.finding_c.hash_code = None
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
        set_duplicate(self.finding_a, self.finding_b)

        self.assertTrue(self.finding_a.duplicate)
        self.assertFalse(self.finding_b.duplicate)
        self.assertEqual(self.finding_a.duplicate_finding.id, self.finding_b.id)
        self.assertEqual(self.finding_b.duplicate_finding, None)
        self.assertEqual(self.finding_b.original_finding.first().id, self.finding_a.id)
        self.assertEqual(self.finding_a.duplicate_finding_set().count(), 1)
        self.assertEqual(self.finding_b.duplicate_finding_set().count(), 1)
        self.assertEqual(self.finding_b.duplicate_finding_set().first().id, self.finding_a.id)

    # A duplicate should not be considered to be an original for another finding
    def test_set_duplicate_exception_1(self):
        self.finding_a.duplicate = True
        self.finding_a.save()
        with self.assertRaisesRegex(Exception, "Existing finding is a duplicate"):
            set_duplicate(self.finding_b, self.finding_a)

    # A finding should never be the duplicate of itself
    def test_set_duplicate_exception_2(self):
        with self.assertRaisesRegex(Exception, "Can not add duplicate to itself"):
            set_duplicate(self.finding_b, self.finding_b)

    # Two duplicate findings can not be duplicates of each other as well
    def test_set_duplicate_exception_3(self):
        set_duplicate(self.finding_a, self.finding_b)
        set_duplicate(self.finding_c, self.finding_b)
        with self.assertRaisesRegex(Exception, "Existing finding is a duplicate"):
            set_duplicate(self.finding_a, self.finding_c)

    # Merge duplicates: If the original of a dupicate is now considered to be a duplicate of a new original the old duplicate should be appended too
    def test_set_duplicate_exception_merge(self):
        # A -> B
        set_duplicate(self.finding_a, self.finding_b)
        # B -> C
        set_duplicate(self.finding_b, self.finding_c)

        self.finding_a = Finding.objects.get(id=self.finding_a.id)
        # A -> C and B -> C
        self.assertTrue(self.finding_b.duplicate)
        self.assertTrue(self.finding_a.duplicate)
        self.assertFalse(self.finding_c.duplicate)
        self.assertEqual(self.finding_b.duplicate_finding.id, self.finding_c.id)
        self.assertEqual(self.finding_a.duplicate_finding.id, self.finding_c.id)
        self.assertEqual(self.finding_c.duplicate_finding, None)
        self.assertEqual(self.finding_a.duplicate_finding_set().count(), 2)
        self.assertEqual(self.finding_b.duplicate_finding_set().count(), 2)
        self.assertEqual(self.finding_a.duplicate_finding.id, self.finding_c.id)

    # if a duplicate is deleted the original should still be present
    def test_set_duplicate_exception_delete_a_duplicate(self):
        set_duplicate(self.finding_a, self.finding_b)
        self.assertEqual(self.finding_b.original_finding.first().id, self.finding_a.id)
        self.finding_a.delete()
        self.assertEqual(self.finding_a.id, None)
        self.assertEqual(self.finding_b.original_finding.first(), None)

    # # if the original is deleted all duplicates should be deleted
    @override_settings(DUPLICATE_CLUSTER_CASCADE_DELETE=True)
    def test_set_duplicate_exception_delete_original_cascade(self):
        set_duplicate(self.finding_a, self.finding_b)
        self.assertEqual(self.finding_b.original_finding.first().id, self.finding_a.id)
        logger.debug('going to delete finding B')
        self.finding_b.delete()
        logger.debug('deleted finding B')
        with self.assertRaises(Finding.DoesNotExist):
            self.finding_a = Finding.objects.get(id=self.finding_a.id)
        self.assertEqual(self.finding_b.id, None)

    # if the original is deleted all duplicates should adjusted to a new original
    @override_settings(DUPLICATE_CLUSTER_CASCADE_DELETE=False)
    def test_set_duplicate_exception_delete_original_duplicates_adapt(self):
        set_duplicate(self.finding_a, self.finding_b)
        set_duplicate(self.finding_c, self.finding_b)
        self.assertEqual(self.finding_b.original_finding.first().id, self.finding_a.id)
        logger.debug('going to delete finding B')
        b_id = self.finding_b.id
        self.finding_b.delete()
        logger.debug('deleted finding B')
        self.finding_a.refresh_from_db()
        self.finding_c.refresh_from_db()
        self.assertEqual(self.finding_a.original_finding.first(), self.finding_c)
        self.assertEqual(self.finding_a.duplicate_finding, None)
        self.assertEqual(self.finding_a.duplicate, False)
        self.assertEqual(self.finding_a.active, True)

        self.assertEqual(self.finding_c.original_finding.first(), None)
        self.assertEqual(self.finding_c.duplicate_finding, self.finding_a)
        self.assertEqual(self.finding_c.duplicate, True)
        self.assertEqual(self.finding_c.active, False)
        with self.assertRaises(Finding.DoesNotExist):
            self.finding_b = Finding.objects.get(id=b_id)

    # if the original is deleted all duplicates should adjusted to a new original
    # in this test there's only 1 duplicate, so that should be marked as no longer duplicate
    @override_settings(DUPLICATE_CLUSTER_CASCADE_DELETE=False)
    def test_set_duplicate_exception_delete_original_1_duplicate_adapt(self):
        set_duplicate(self.finding_a, self.finding_b)
        self.assertEqual(self.finding_b.original_finding.first().id, self.finding_a.id)
        logger.debug('going to delete finding B')
        b_id = self.finding_b.id
        self.finding_b.delete()
        logger.debug('deleted finding B')
        self.finding_a.refresh_from_db()
        self.assertEqual(self.finding_a.original_finding.first(), None)
        self.assertEqual(self.finding_a.duplicate_finding, None)
        self.assertEqual(self.finding_a.duplicate, False)
        self.assertEqual(self.finding_a.active, True)
        with self.assertRaises(Finding.DoesNotExist):
            self.finding_b = Finding.objects.get(id=b_id)

    def test_loop_relations_for_one(self):
        # B -> B
        self.finding_b.duplicate = True
        self.finding_b.duplicate_finding = self.finding_b
        super(Finding, self.finding_b).save()
        candidates = Finding.objects.filter(duplicate_finding__isnull=False, original_finding__isnull=False).count()
        self.assertEqual(candidates, 1)
        loop_count = fix_loop_duplicates()
        self.assertEqual(loop_count, 0)
        candidates = Finding.objects.filter(duplicate_finding__isnull=False, original_finding__isnull=False).count()
        self.assertEqual(candidates, 0)

    # if two findings are connected with each other the fix_loop function should detect and remove the loop
    def test_loop_relations_for_two(self):

        # A -> B -> B
        set_duplicate(self.finding_a, self.finding_b)
        self.finding_b.duplicate = True
        self.finding_b.duplicate_finding = self.finding_a

        super(Finding, self.finding_a).save()
        super(Finding, self.finding_b).save()

        loop_count = fix_loop_duplicates()
        self.assertEqual(loop_count, 0)

        candidates = Finding.objects.filter(duplicate_finding__isnull=False, original_finding__isnull=False).count()
        self.assertEqual(candidates, 0)

        # Get latest status
        self.finding_a = Finding.objects.get(id=self.finding_a.id)
        self.finding_b = Finding.objects.get(id=self.finding_b.id)

        # assert that A -> B  (or B -> A)?
        if self.finding_a.duplicate_finding:
            self.assertTrue(self.finding_a.duplicate)
            self.assertEqual(self.finding_a.original_finding.count(), 0)
        else:
            self.assertFalse(self.finding_a.duplicate)
            self.assertEqual(self.finding_a.original_finding.count(), 1)

        if self.finding_b.duplicate_finding:
            self.assertTrue(self.finding_b.duplicate)
            self.assertEqual(self.finding_b.original_finding.count(), 0)
        else:
            self.assertFalse(self.finding_b.duplicate)
            self.assertEqual(self.finding_b.original_finding.count(), 1)

    # Similar Loop detection and deletion for three findings
    def test_loop_relations_for_three(self):

        # A -> B, B -> C, C -> A
        set_duplicate(self.finding_a, self.finding_b)
        self.finding_b.duplicate = True
        self.finding_b.duplicate_finding = self.finding_c
        self.finding_c.duplicate = True
        self.finding_c.duplicate_finding = self.finding_a

        super(Finding, self.finding_a).save()
        super(Finding, self.finding_b).save()
        super(Finding, self.finding_c).save()

        loop_count = fix_loop_duplicates()
        self.assertEqual(loop_count, 0)

        # Get latest status
        self.finding_a = Finding.objects.get(id=self.finding_a.id)
        self.finding_b = Finding.objects.get(id=self.finding_b.id)
        self.finding_c = Finding.objects.get(id=self.finding_c.id)

        if self.finding_a.duplicate_finding:
            self.assertTrue(self.finding_a.duplicate)
            self.assertEqual(self.finding_a.original_finding.count(), 0)
        else:
            self.assertFalse(self.finding_a.duplicate)
            self.assertEqual(self.finding_a.original_finding.count(), 2)

        if self.finding_b.duplicate_finding:
            self.assertTrue(self.finding_b.duplicate)
            self.assertEqual(self.finding_b.original_finding.count(), 0)
        else:
            self.assertFalse(self.finding_b.duplicate)
            self.assertEqual(self.finding_b.original_finding.count(), 2)

        if self.finding_c.duplicate_finding:
            self.assertTrue(self.finding_c.duplicate)
            self.assertEqual(self.finding_c.original_finding.count(), 0)
        else:
            self.assertFalse(self.finding_c.duplicate)
            self.assertEqual(self.finding_c.original_finding.count(), 2)

    # Another loop-test for 4 findings
    def test_loop_relations_for_four(self):
        self.finding_d = Finding.objects.get(id=4)
        self.finding_d.pk = None
        self.finding_d.duplicate = False
        self.finding_d.duplicate_finding = None
        self.finding_d.save()

        # A -> B, B -> C, C -> D, D -> A
        set_duplicate(self.finding_a, self.finding_b)
        self.finding_b.duplicate = True
        self.finding_b.duplicate_finding = self.finding_c
        self.finding_c.duplicate = True
        self.finding_c.duplicate_finding = self.finding_d
        self.finding_d.duplicate = True
        self.finding_d.duplicate_finding = self.finding_a

        super(Finding, self.finding_a).save()
        super(Finding, self.finding_b).save()
        super(Finding, self.finding_c).save()
        super(Finding, self.finding_d).save()

        loop_count = fix_loop_duplicates()
        self.assertEqual(loop_count, 0)

        # Get latest status
        self.finding_a = Finding.objects.get(id=self.finding_a.id)
        self.finding_b = Finding.objects.get(id=self.finding_b.id)
        self.finding_c = Finding.objects.get(id=self.finding_c.id)
        self.finding_d = Finding.objects.get(id=self.finding_d.id)

        if self.finding_a.duplicate_finding:
            self.assertTrue(self.finding_a.duplicate)
            self.assertEqual(self.finding_a.original_finding.count(), 0)
        else:
            self.assertFalse(self.finding_a.duplicate)
            self.assertEqual(self.finding_a.original_finding.count(), 3)

        if self.finding_b.duplicate_finding:
            self.assertTrue(self.finding_b.duplicate)
            self.assertEqual(self.finding_b.original_finding.count(), 0)
        else:
            self.assertFalse(self.finding_b.duplicate)
            self.assertEqual(self.finding_b.original_finding.count(), 3)

        if self.finding_c.duplicate_finding:
            self.assertTrue(self.finding_c.duplicate)
            self.assertEqual(self.finding_c.original_finding.count(), 0)
        else:
            self.assertFalse(self.finding_c.duplicate)
            self.assertEqual(self.finding_c.original_finding.count(), 3)

        if self.finding_d.duplicate_finding:
            self.assertTrue(self.finding_d.duplicate)
            self.assertEqual(self.finding_d.original_finding.count(), 0)
        else:
            self.assertFalse(self.finding_d.duplicate)
            self.assertEqual(self.finding_d.original_finding.count(), 3)

    # Similar Loop detection and deletion for three findings
    def test_list_relations_for_three(self):

        # A -> B, B -> C
        set_duplicate(self.finding_a, self.finding_b)
        self.finding_b.duplicate = True
        self.finding_b.duplicate_finding = self.finding_c

        super(Finding, self.finding_a).save()
        super(Finding, self.finding_b).save()
        super(Finding, self.finding_c).save()

        loop_count = fix_loop_duplicates()
        self.assertEqual(loop_count, 0)

        self.finding_a = Finding.objects.get(id=self.finding_a.id)
        self.finding_b = Finding.objects.get(id=self.finding_b.id)
        self.finding_c = Finding.objects.get(id=self.finding_c.id)

        # A -> C, B -> C
        self.assertTrue(self.finding_b.duplicate)
        self.assertTrue(self.finding_a.duplicate)
        self.assertFalse(self.finding_c.duplicate)
        self.assertEqual(self.finding_b.duplicate_finding.id, self.finding_c.id)
        self.assertEqual(self.finding_a.duplicate_finding.id, self.finding_c.id)
        self.assertEqual(self.finding_c.duplicate_finding, None)
        self.assertEqual(self.finding_a.duplicate_finding_set().count(), 2)
        self.assertEqual(self.finding_b.duplicate_finding_set().count(), 2)

    def test_list_relations_for_three_reverse(self):
        # C -> B, B -> A
        set_duplicate(self.finding_c, self.finding_b)
        self.finding_b.duplicate = True
        self.finding_b.duplicate_finding = self.finding_a

        super(Finding, self.finding_a).save()
        super(Finding, self.finding_b).save()
        super(Finding, self.finding_c).save()

        loop_count = fix_loop_duplicates()
        self.assertEqual(loop_count, 0)

        self.finding_a = Finding.objects.get(id=self.finding_a.id)
        self.finding_b = Finding.objects.get(id=self.finding_b.id)
        self.finding_c = Finding.objects.get(id=self.finding_c.id)

        # B -> A, C -> A
        self.assertTrue(self.finding_b.duplicate)
        self.assertTrue(self.finding_c.duplicate)
        self.assertFalse(self.finding_a.duplicate)
        self.assertEqual(self.finding_b.duplicate_finding.id, self.finding_a.id)
        self.assertEqual(self.finding_c.duplicate_finding.id, self.finding_a.id)
        self.assertEqual(self.finding_a.duplicate_finding, None)
        self.assertEqual(self.finding_c.duplicate_finding_set().count(), 2)
        self.assertEqual(self.finding_b.duplicate_finding_set().count(), 2)

    def test_delete_all_engagements(self):
        # make sure there is no exception when deleting all engagements
        for engagement in Engagement.objects.all().order_by('id'):
            engagement.delete()

    def test_delete_all_products(self):
        # make sure there is no exception when deleting all engagements
        for product in Product.objects.all().order_by('id'):
            product.delete()
