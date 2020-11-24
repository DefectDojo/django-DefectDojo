import logging
from crum import impersonate
from dojo.models import System_Settings, User, Product, Engagement
from dojo import utils
from datetime import date
from rest_framework.test import APITestCase

"""
Fixture description
- All engagement contain an import of the same anchore json file
- Engagement 7 is the original, and contains original findings. All other engagements only contain duplicates.
- Engagement 8 should be deleted by the autodelete, and therefore not be found anymore (404)
- Engagement 9 should not be deleted because of the lock tag
- Engagement 10 should not be deleted because of one comment in a finding
- Engagement 11 is a copy test, much like 8, would not be taken into consideration for deletion.
- Engagement 12 will be created here so that its created date is too recent to be taken into consideration by autodelete. It should therefore not be deleted.
"""
logger = logging.getLogger(__name__)


class AutoDeleteEngagement(APITestCase):
    # fixtures = ['test_autodelete.json']
    fixtures = ['dojo_testdata.json']

    def setUp(self):
        testuser = User.objects.get(username='admin')
        self.client.force_login(testuser)

    @classmethod
    def setUpClass(cls):
        super(AutoDeleteEngagement, cls).setUpClass()
        logger.info("Setting up proper system settings properties")
        cls.system_settings = System_Settings.objects.get()
        cls.system_settings.engagement_auto_delete_enable = True
        cls.system_settings.engagement_auto_delete_days = 10
        cls.system_settings.engagement_auto_close_lock_tag = 'donotdelete'
        cls.system_settings.enable_deduplication = True
        cls.system_settings.enable_auditlog = False
        cls.system_settings.save()
        # run the auto-delete command to then check the results within the tests
        utils.auto_delete_engagements()

    def run(self, result=None):
        testuser = User.objects.get(username='admin')
        testuser.usercontactinfo.block_execution = True
        testuser.save()

        # unit tests are running without any user, which will result in actions like dedupe happening in the celery process
        # this doesn't work in unittests as unittests are using an in memory sqlite database and celery can't see the data
        # so we're running the test under the admin user context and set block_execution to True
        with impersonate(testuser):
            super().run(result)

    def test_engagement_7_is_not_deleted(self):
        response = self.client.get('/engagement/7')
        self.assertEqual(response.status_code, 200)

    def test_engagement_8_is_deleted(self):
        response = self.client.get('/engagement/8')
        self.assertEqual(response.status_code, 404)

    def test_engagement_9_is_not_deleted(self):
        response = self.client.get('/engagement/9')
        self.assertEqual(response.status_code, 200)

    def test_engagement_10_is_not_deleted(self):
        response = self.client.get('/engagement/10')
        self.assertEqual(response.status_code, 200)

    def test_too_recent_engagement_is_not_deleted(self):
        new_engagement = Engagement.objects.create(product=Product.objects.get(id=1),
                                                   target_start=date.today(),
                                                   target_end=date.today())
        response = self.client.get('/engagement/{}'.format(new_engagement.pk))
        self.assertEqual(response.status_code, 200)

    def test_copy_made_more_recent_engagement_is_not_deleted(self):
        new_engagement = self.copy_and_reset_engagement(id=7)
        new_engagement.save()
        response = self.client.get('/engagement/{}'.format(new_engagement.pk))
        self.assertEqual(response.status_code, 200)

    def copy_and_reset_engagement(self, id):
        original_engagement = Engagement.objects.get(id=id)
        new_engagement = original_engagement
        new_engagement.pk = 11
        new_engagement.created = date.today().isoformat()
        return new_engagement
