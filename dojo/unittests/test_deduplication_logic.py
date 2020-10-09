from django.test import TestCase
from dojo.models import Finding, User, Product, Endpoint, Endpoint_Status, Test, Engagement
from dojo.models import System_Settings
from crum import impersonate
import logging
logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")

loglevel = logging.DEBUG
logging.basicConfig(level=loglevel)

# WIP

# things to consider:
# - cross scanner deduplication is still flaky as if some scanners don't provide severity, but another doesn, the hashcode will be different so no deduplication happens.
#   so I couldn't create any good tests
# - hash_code is only calculated once and never changed. should we add a feature to run dedupe when somebody modifies a finding? bulk edit action to trigger dedupe?

# test data summary
# product 1: Python How-to
#       engagement 2: April monthly engagement
#               test 13: ZAP Scan (algo=hash_code, dynamic=True)
#               no findings
#               endpoints
#                       2: ftp://localhost/
#                       1: http://127.0.0.1/endpoint/420/edit/
#                       3: ssh:127.0.1
#               endpoint statuses
#                       1: dojo.Endpoint.None dojo.Finding.None 1 2020-07-01 00:00:00+00:00 2020-07-01 17:45:39.791907+00:00 False None None False False False ftp://localhost/ High Impact Test Finding
# product 2: Security How-to
#       engagement 1: 1st Quarter Engagement
#               test 3: ZAP Scan (algo=hash_code, dynamic=True)
#               findings:
#                       2   : "High Impact Test Fin": High : act: True : ver: True : mit: False: dup: False: dup_id: None: hash_code: 8cba854f0b70f8a25064952402fbe30c728c0017b83c245d786366956044e0bf: eps: 0: notes: []
#                       3   : "High Impact Test Fin": High : act: True : ver: True : mit: False: dup: True : dup_id: 2   : hash_code: 8cba854f0b70f8a25064952402fbe30c728c0017b83c245d786366956044e0bf: eps: 0: notes: []
#                       4   : "High Impact Test Fin": High : act: True : ver: True : mit: False: dup: True : dup_id: 2   : hash_code: 8cba854f0b70f8a25064952402fbe30c728c0017b83c245d786366956044e0bf: eps: 0: notes: []
#                       5   : "High Impact Test Fin": High : act: True : ver: True : mit: False: dup: True : dup_id: 2   : hash_code: 8cba854f0b70f8a25064952402fbe30c728c0017b83c245d786366956044e0bf: eps: 0: notes: []
#                       6   : "High Impact Test Fin": High : act: True : ver: True : mit: False: dup: True : dup_id: 2   : hash_code: 8cba854f0b70f8a25064952402fbe30c728c0017b83c245d786366956044e0bf: eps: 0: notes: []
#                       7   : "DUMMY FINDING       ": High : act: False: ver: False: mit: False: dup: False: dup_id: None: hash_code: c89d25e445b088ba339908f68e15e3177b78d22f3039d1bfea51c4be251bf4e0: eps: 0: notes: [1]
#               endpoints
#                       2: ftp://localhost/
#                       1: http://127.0.0.1/endpoint/420/edit/
#                       3: ssh:127.0.1
#               endpoint statuses
#                       1: dojo.Endpoint.None dojo.Finding.None 1 2020-07-01 00:00:00+00:00 2020-07-01 17:45:39.791907+00:00 False None None False False False ftp://localhost/ High Impact Test Finding
#               test 14: ZAP Scan (algo=hash_code, dynamic=True)
#               no findings
#               endpoints
#                       2: ftp://localhost/
#                       1: http://127.0.0.1/endpoint/420/edit/
#                       3: ssh:127.0.1
#               endpoint statuses
#                       1: dojo.Endpoint.None dojo.Finding.None 1 2020-07-01 00:00:00+00:00 2020-07-01 17:45:39.791907+00:00 False None None False False False ftp://localhost/ High Impact Test Finding
#       engagement 4: April monthly engagement
#               test 4: ZAP Scan (algo=hash_code, dynamic=True)
#               no findings
#               endpoints
#                       2: ftp://localhost/
#                       1: http://127.0.0.1/endpoint/420/edit/
#                       3: ssh:127.0.1
#               endpoint statuses
#                       1: dojo.Endpoint.None dojo.Finding.None 1 2020-07-01 00:00:00+00:00 2020-07-01 17:45:39.791907+00:00 False None None False False False ftp://localhost/ High Impact Test Finding
#       engagement 3: weekly engagement
#               test 33: Generic Findings Import (algo=legacy, dynamic=False)
#               findings:
#                       22  : "Low Impact Test Find": Low  : act: True : ver: True : mit: False: dup: False: dup_id: None: hash_code: 5f272ec29b29d56ca08eba26435bdb225ae4956812c10fce872a6143b73474ba: eps: 0: notes: []
#                       23  : "Low Impact Test Find": Low  : act: True : ver: True : mit: False: dup: True : dup_id: 22  : hash_code: 5f272ec29b29d56ca08eba26435bdb225ae4956812c10fce872a6143b73474ba: eps: 0: notes: []
#                       24  : "Low Impact Test Find": Low  : act: True : ver: True : mit: False: dup: True : dup_id: 22  : hash_code: 5f272ec29b29d56ca08eba26435bdb225ae4956812c10fce872a6143b73474ba: eps: 0: notes: []
#               endpoints
#                       2: ftp://localhost/
#                       1: http://127.0.0.1/endpoint/420/edit/
#                       3: ssh:127.0.1
#               endpoint statuses
#                       1: dojo.Endpoint.None dojo.Finding.None 1 2020-07-01 00:00:00+00:00 2020-07-01 17:45:39.791907+00:00 False None None False False False ftp://localhost/ High Impact Test Finding
# product 3: Security Podcast


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

        self.log_summary()

    # def tearDown(self):
        # self.log_summary()
        # self.log_summary(test=33)
        # self.log_summary(product=2)

    # all engagements in the test data have deduplication_on_engagement set to true

    # legacy algo:  findings 23, 24, 25 in test 33 are scan_Type Generic Findings Import which uses the legacy algo

    def test_identical_legacy(self):
        # 24 is already a duplicate of 22 let's see what happens if we create an identical finding (but reset status)
        # expect: marked as duplicate
        finding_new, finding_24 = self.copy_and_reset_finding(id=24)
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=24, duplicate=True, duplicate_finding_id=finding_24.duplicate_finding.id, hash_code=finding_24.hash_code)

    def test_identical_ordering_legacy(self):
        finding_22 = Finding.objects.get(id=22)
        # 23 is already a duplicate of 22, but let's reset it's status. then update 24 and see if it gets marked as duplicate of 22 or 23
        # expect: marked as duplicate of 23 as 23 is older (date field on finding)
        # but feature or BUG? it will get marked as duplicate of 22 as it becomes earlier in the findings list (or ordering is by date desc)

        finding_23 = Finding.objects.get(id=23)
        finding_23.duplicate = False
        finding_23.duplicate_finding = None
        finding_23.active = True
        finding_23.save(dedupe_option=False)

        self.assert_finding(finding_23, duplicate=False, hash_code=finding_22.hash_code)

        # create a copy of 22
        finding_new, finding_22 = self.copy_and_reset_finding(id=22)
        finding_new.save()

        self.assert_finding(finding_new, not_pk=22, duplicate=True, duplicate_finding_id=finding_22.id, hash_code=finding_22.hash_code)
        # self.assert_finding(finding_new, not_pk=22, duplicate=True, duplicate_finding_id=finding_23.id, hash_code=finding_22.hash_code)

    def test_identical_except_title_legacy(self):
        # 24 is already a duplicate of 22, let's see what happens if we create an identical finding with different title (and reset status)
        # expect: NOT marked as duplicate as title is part of hash_code calculation
        finding_new, finding_4 = self.copy_and_reset_finding(id=4)
        finding_new.title = 'the best title'
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=24, duplicate=False, not_hash_code=finding_4.hash_code)
        return

    def test_identical_except_description_legacy(self):
        # 24 is already a duplicate of 22, let's see what happens if we create an identical finding with different description (and reset status)
        # expect: not marked as duplicate as legacy sees description as leading for hash_code
        finding_new, finding_24 = self.copy_and_reset_finding(id=24)
        finding_new.description = 'useless finding'
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=24, duplicate=False, not_hash_code=finding_24.hash_code)
        return

    def test_identical_except_line_legacy(self):
        # 24 is already a duplicate of 22, let's see what happens if we create an identical finding with different line (and reset status)
        # expect: not marked as duplicate
        finding_new, finding_24 = self.copy_and_reset_finding(id=24)
        finding_new.line = 666
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=24, duplicate=False, not_hash_code=finding_24.hash_code)
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

    def test_dedupe_inside_engagement_legacy(self):
        # finding 2 in engagement 1
        # make a copy and store it in engagement 2, test 4
        # should not result in being marked as duplicate as it crosses engagement boundaries
        # both test 3 and 4 are ZAP scans (cross scanner dedupe is still not working very well)
        finding_new, finding_22 = self.copy_and_reset_finding(id=22)
        # create new engagment + test in same product
        test_new, eng_new = self.create_new_test_and_engagment_from_finding(finding_22)

        finding_new.test = test_new
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=22, duplicate=False, hash_code=finding_22.hash_code)
        return

    def test_dedupe_not_inside_engagement_legacy(self):
        # finding 2 in engagement 1
        # make a copy and store it in engagement 2, test 4
        # should result in being marked as duplicate as dedupe inside engagement is set to False
        # both test 3 and 4 are ZAP scans (cross scanner dedupe is still not working very well)
        finding_new, finding_22 = self.copy_and_reset_finding(id=22)

        # dedupe_inside_engagment must be false before cloning engagement
        self.set_dedupe_inside_engagement(False)
        # create new engagment + test in same product
        test_new, eng_new = self.create_new_test_and_engagment_from_finding(finding_22)

        finding_new.test = test_new
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=22, duplicate=True, duplicate_finding_id=22, hash_code=finding_22.hash_code)
        return

    # legacy: if file_path and line or both empty and there are no endpoints, no dedupe will happen. Is this desirable or a BUG?
    def test_identical_no_filepath_no_line_no_endpoints_legacy(self):
        finding_new, finding_22 = self.copy_and_reset_finding(id=22)
        finding_new.file_path = None
        finding_new.line = None
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=22, duplicate=False)

    def test_identical_legacy_with_identical_endpoints_static(self):
        finding_new, finding_24 = self.copy_and_reset_finding_add_endpoints(id=24, static=True, dynamic=False)  # has myhost.com, myhost2.com
        finding_new.save()

        # create an identical copy of the new finding with the same endpoints. it should be marked as duplicate
        finding_new2, finding_new = self.copy_and_reset_finding(id=finding_new.id)
        finding_new2.save(dedupe_option=False)

        ep1 = Endpoint(product=finding_new2.test.engagement.product, finding=finding_new2, host="myhost.com", protocol="https")
        ep1.save()
        ep2 = Endpoint(product=finding_new2.test.engagement.product, finding=finding_new2, host="myhost2.com", protocol="https")
        ep2.save()
        finding_new2.endpoints.add(ep1)
        finding_new2.endpoints.add(ep2)
        finding_new2.save()

        self.assert_finding(finding_new2, not_pk=finding_new.pk, duplicate=True, duplicate_finding_id=finding_new.id, hash_code=finding_new.hash_code, not_hash_code=finding_24.hash_code)

        return

    def test_identical_legacy_extra_endpoints_static(self):
        finding_new, finding_24 = self.copy_and_reset_finding_add_endpoints(id=24, static=True, dynamic=False)  # has myhost.com, myhost2.com
        finding_new.save()

        # create a new finding with 3 endpoints (so 1 extra)
        finding_new3, finding_new = self.copy_and_reset_finding(id=finding_new.id)
        finding_new3.save(dedupe_option=False)
        ep1 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost.com", protocol="https")
        ep1.save()
        ep2 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost2.com", protocol="https")
        ep2.save()
        ep3 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost3.com", protocol="https")
        ep3.save()
        finding_new3.endpoints.add(ep1)
        finding_new3.endpoints.add(ep2)
        finding_new3.endpoints.add(ep3)
        finding_new3.save()

        # expect: marked as duplicate as the requirement for static findings is that the new finding has to contain all the endpoints of the existing finding (extra is no problem)
        #         hash_code not affected by endpoints
        self.assert_finding(finding_new3, not_pk=finding_new.pk, duplicate=True, duplicate_finding_id=finding_new.id, hash_code=finding_new.hash_code, not_hash_code=finding_24.hash_code)

    def test_identical_legacy_different_endpoints_static(self):
        finding_new, finding_24 = self.copy_and_reset_finding_add_endpoints(id=24, static=True, dynamic=False)  # has myhost.com, myhost2.com
        finding_new.save()

        # create an identical copy of the new finding, but with different endpoints
        finding_new3, finding_new = self.copy_and_reset_finding(id=finding_new.id)
        finding_new3.save(dedupe_option=False)
        ep1 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost4.com", protocol="https")
        ep1.save()
        ep2 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost2.com", protocol="https")
        ep2.save()
        finding_new3.endpoints.add(ep1)
        finding_new3.endpoints.add(ep2)
        finding_new3.save()

        # expect: not marked as duplicate as the requirement for static findings is that the new finding has to contain all the endpoints of the existing finding and this is not met
        #         hash_code not affected by endpoints
        self.assert_finding(finding_new3, not_pk=finding_new.pk, duplicate=False, hash_code=finding_new.hash_code, not_hash_code=finding_24.hash_code)

    def test_identical_legacy_no_endpoints_static(self):
        finding_new, finding_24 = self.copy_and_reset_finding_add_endpoints(id=24, static=True, dynamic=False)  # has myhost.com, myhost2.com
        finding_new.save()

        # create an identical copy of the new finding, but with 1 extra endpoint. should not be marked as duplicate
        finding_new3, finding_new = self.copy_and_reset_finding(id=finding_new.id)
        finding_new3.save(dedupe_option=False)
        finding_new3.save()

        # expect not marked as duplicate as the new finding doesn't have endpoints and we don't have filepath/line
        self.assert_finding(finding_new3, not_pk=finding_new.pk, duplicate=False, hash_code=finding_new.hash_code, not_hash_code=finding_24.hash_code)

    def test_identical_legacy_with_identical_endpoints_dynamic(self):
        finding_new, finding_24 = self.copy_and_reset_finding_add_endpoints(id=24, static=True, dynamic=False)  # has myhost.com, myhost2.com
        finding_new.save()

        # create an identical copy of the new finding. it should be marked as duplicate
        finding_new2, finding_new = self.copy_and_reset_finding(id=finding_new.id)
        finding_new2.save(dedupe_option=False)

        ep1 = Endpoint(product=finding_new2.test.engagement.product, finding=finding_new2, host="myhost.com", protocol="https")
        ep1.save()
        ep2 = Endpoint(product=finding_new2.test.engagement.product, finding=finding_new2, host="myhost2.com", protocol="https")
        ep2.save()
        finding_new2.endpoints.add(ep1)
        finding_new2.endpoints.add(ep2)
        finding_new2.save()

        self.assert_finding(finding_new2, not_pk=finding_new.pk, duplicate=True, duplicate_finding_id=finding_new.id, hash_code=finding_new.hash_code, not_hash_code=finding_24.hash_code)

        return

    def test_identical_legacy_extra_endpoints_dynamic(self):
        finding_new, finding_24 = self.copy_and_reset_finding_add_endpoints(id=24)
        finding_new.save()

        # create an identical copy of the new finding, but with 1 extra endpoint.
        finding_new3, finding_new = self.copy_and_reset_finding(id=finding_new.id)
        finding_new3.save(dedupe_option=False)
        ep1 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost.com", protocol="https")
        ep1.save()
        ep2 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost2.com", protocol="https")
        ep2.save()
        ep3 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost3.com", protocol="https")
        ep3.save()
        finding_new3.endpoints.add(ep1)
        finding_new3.endpoints.add(ep2)
        finding_new3.endpoints.add(ep3)
        finding_new3.save()

        # expect: not marked as duplicate, hash_code affected by endpoints
        self.assert_finding(finding_new3, not_pk=finding_new.pk, duplicate=False, not_hash_code=finding_new.hash_code)

    def test_identical_legacy_different_endpoints_dynamic(self):
        # this test is using the pattern currently in use in the import / serializers.py.
        #  - save finding first with dedupe-false
        #  - add endpoints
        #  - safe finding again with endpoints attached, dedupe=True (default) -> hash_code gets computed
        # create a new finding with 3 endpoints (so 1 extra)
        # expect: not marked as duplicate as endpoints need to be 100% equal for dynamic findings (host+port)
        #         hash_code not affected by endpoints
        finding_new, finding_24 = self.copy_and_reset_finding_add_endpoints(id=24)
        finding_new.save()

        # create an identical copy of the new finding, but with 1 extra endpoint. should not be marked as duplicate
        finding_new3, finding_new = self.copy_and_reset_finding(id=finding_new.id)
        finding_new3.save(dedupe_option=False)
        ep1 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost4.com", protocol="https")
        ep1.save()
        ep2 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost2.com", protocol="https")
        ep2.save()
        finding_new3.endpoints.add(ep1)
        finding_new3.endpoints.add(ep2)
        finding_new3.save()

        # expect: not marked as duplicate, hash_code affected by endpoints
        self.assert_finding(finding_new3, not_pk=finding_new.pk, duplicate=False, not_hash_code=finding_new.hash_code)

    def test_identical_legacy_no_endpoints_dynamic(self):
        finding_new, finding_24 = self.copy_and_reset_finding_add_endpoints(id=24)
        finding_new.save()

        # create an identical copy of the new finding, but with no endpoints
        finding_new3, finding_new = self.copy_and_reset_finding(id=finding_new.id)
        finding_new3.save(dedupe_option=False)
        finding_new3.save()

        # expect: not marked as duplicate, hash_code affected by endpoints
        self.assert_finding(finding_new3, not_pk=finding_new.pk, duplicate=False, not_hash_code=finding_new.hash_code)

    # hash_code based algorithm tests

    # existing findings in test 3 are from ZAP scanner, which uses hash_code algorithm with ['title', 'cwe', 'endpoints', 'severity']
    def test_identical_hash_code(self):
        # 4 is already a duplicate of 2, let's see what happens if we create an identical finding (but reset status)
        # expect: marked as duplicate
        finding_new, finding_4 = self.copy_and_reset_finding(id=4)
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=4, duplicate=True, duplicate_finding_id=finding_4.duplicate_finding.id, hash_code=finding_4.hash_code)
        return

    def test_identical_ordering_hash_code(self):
        finding_2 = Finding.objects.get(id=2)
        # 3 is already a duplicate of 2, but let's reset it's status. then update 24 and see if it gets marked as duplicate of 22 or 23
        # expect: marked as duplicate of 3 as 3 is older (date field on finding)
        # but feature or BUG? it will get marked as duplicate of 2 as it becomes earlier in the findings list (or ordering is by date desc)

        finding_3 = Finding.objects.get(id=3)
        finding_3.duplicate = False
        finding_3.duplicate_finding = None
        finding_3.active = True
        finding_3.save(dedupe_option=False)

        self.assert_finding(finding_3, duplicate=False, hash_code=finding_2.hash_code)

        # create a copy of 2
        finding_new, finding_2 = self.copy_and_reset_finding(id=2)
        finding_new.save()

        self.assert_finding(finding_new, not_pk=2, duplicate=True, duplicate_finding_id=finding_2.id, hash_code=finding_2.hash_code)
        # self.assert_finding(finding_new, not_pk=2, duplicate=True, duplicate_finding_id=finding_3.id, hash_code=finding_2.hash_code)

    def test_identical_except_title_hash_code(self):
        # 4 is already a duplicate of 2, let's see what happens if we create an identical finding with different title (and reset status)
        # expect: NOT marked as duplicate as title is part of hash_code calculation
        finding_new, finding_4 = self.copy_and_reset_finding(id=4)
        finding_new.title = 'the best title'
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=4, duplicate=False, not_hash_code=finding_4.hash_code)
        return

    def test_identical_except_description_hash_code(self):
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

    def test_dedupe_inside_engagement_hash_code(self):
        # finding 2 in engagement 1
        # make a copy and store it in engagement 2, test 4
        # should not result in being marked as duplicate as it crosses engagement boundaries
        # both test 3 and 4 are ZAP scans (cross scanner dedupe is still not working very well)
        finding_new, finding_2 = self.copy_and_reset_finding(id=2)
        finding_new.test = Test.objects.get(id=4)
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=2, duplicate=False, hash_code=finding_2.hash_code)
        return

    def test_dedupe_not_inside_engagement_hash_code(self):
        # finding 2 in engagement 1
        # make a copy and store it in engagement 2, test 4
        # should result in being marked as duplicate as dedupe inside engagement is set to False
        # both test 3 and 4 are ZAP scans (cross scanner dedupe is still not working very well)
        self.set_dedupe_inside_engagement(False)

        finding_new, finding_2 = self.copy_and_reset_finding(id=2)
        finding_new.test = Test.objects.get(id=4)
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=2, duplicate=True, duplicate_finding_id=2, hash_code=finding_2.hash_code)
        return

    # hash_code: if file_path and line or both empty and there are no endpoints, dedupe should happen (as opposed to legacy dedupe)
    def test_identical_no_filepath_no_line_no_endpoints_hash_code(self):
        finding_new, finding_2 = self.copy_and_reset_finding(id=2)
        finding_new.file_path = None
        finding_new.line = None
        finding_new.save(dedupe_option=True)

        self.assert_finding(finding_new, not_pk=2, duplicate=True, duplicate_finding_id=2, hash_code=finding_2.hash_code)

    def test_identical_hash_code_with_identical_endpoints(self):
        finding_new, finding_4 = self.copy_and_reset_finding_add_endpoints(id=4)  # has myhost.com, myhost2.com
        finding_new.save()

        # create an identical copy of the new finding, with the same endpoints
        finding_new2, finding_new = self.copy_and_reset_finding(id=finding_new.id)
        finding_new2.save(dedupe_option=False)

        ep1 = Endpoint(product=finding_new2.test.engagement.product, finding=finding_new2, host="myhost.com", protocol="https")
        ep1.save()
        ep2 = Endpoint(product=finding_new2.test.engagement.product, finding=finding_new2, host="myhost2.com", protocol="https")
        ep2.save()
        finding_new2.endpoints.add(ep1)
        finding_new2.endpoints.add(ep2)
        finding_new2.save()

        # expect: not marked as duplicate, hash_code affected by endpoints
        self.assert_finding(finding_new2, not_pk=finding_new.pk, duplicate=True, duplicate_finding_id=finding_new.id, hash_code=finding_new.hash_code, not_hash_code=finding_4.hash_code)

        return

    def test_identical_hash_code_with_different_endpoints(self):
        finding_new, finding_4 = self.copy_and_reset_finding_add_endpoints(id=4)
        # save with dedupe so hash_code contains endpoints
        finding_new.save()

        # create an identical copy of the new finding, but with 1 extra endpoint. should not be marked as duplicate
        finding_new3, finding_new = self.copy_and_reset_finding(id=finding_new.id)
        finding_new3.save(dedupe_option=False)
        ep1 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost4.com", protocol="https")
        ep1.save()
        ep2 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost2.com", protocol="https")
        ep2.save()
        ep3 = Endpoint(product=finding_new3.test.engagement.product, finding=finding_new3, host="myhost3.com", protocol="https")
        ep3.save()
        finding_new3.endpoints.add(ep1)
        finding_new3.endpoints.add(ep2)
        finding_new3.endpoints.add(ep3)
        finding_new3.save()

        # expect: not marked as duplicate, hash_code affected by endpoints
        self.assert_finding(finding_new3, not_pk=finding_new.pk, duplicate=False, not_hash_code=finding_4.hash_code)

    # def test_identical_unique_id(self):
    #     return

    # def test_identical_ordering_unique_id(self):
    #     return

    # def test_title_description_line_filepath_different_unique_id(self):
    #     return

    # def test_dedupe_inside_engagement_unique_id(self):
    #     return

    # def test_dedupe_not_inside_engagement_unique_id(self):
    #     return

    # def test_identical_unique_id_or_hash_code(self):
    #     return

    # def test_identical_ordering_unique_id_or_hash_code(self):
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

    # # inside/outside eng

    # # some extra tests

    # hash_code currently is only created on finding creation and after that never changed. feature or BUG?
    def test_hash_code_onetime(self):
        finding_new, finding_2 = self.copy_and_reset_finding(id=2)
        self.assertEqual(finding_new.hash_code, None)

        finding_new.save()
        self.assertTrue(finding_new.hash_code)  # True -> not None
        hash_code_at_creation = finding_new.hash_code

        finding_new.title = 'new_title'
        finding_new.cve = 999

        # both title and cve affect hash_code for ZAP scans, but not here because hash_code was already calculated
        finding_new.save()
        self.assertEqual(finding_new.hash_code, hash_code_at_creation)
        finding_new.save(dedupe_option=False)
        self.assertEqual(finding_new.hash_code, hash_code_at_creation)
        finding_new.save(dedupe_option=True)
        self.assertEqual(finding_new.hash_code, hash_code_at_creation)

    def test_identical_legacy_dedupe_option_true_false(self):
        # 24 is already a duplicate of 22 let's see what happens if we create an identical finding (but reset status)
        # expect: not marked as duplicate with dedupe_option-False
        finding_new, finding_24 = self.copy_and_reset_finding(id=24)
        finding_new.save(dedupe_option=False)
        self.assert_finding(finding_new, not_pk=24, duplicate=False, hash_code=None)

        # expect duplicate when saving with dedupe_option=True
        finding_new.save(dedupe_option=True)
        self.assert_finding(finding_new, not_pk=24, duplicate=True, duplicate_finding_id=finding_24.duplicate_finding.id, hash_code=finding_24.hash_code)

    def test_duplicate_after_modification(self):
        # we copy a finding but change some important fields so it's no longer a duplicate
        # expect: not marked as duplicate with dedupe_option-False
        finding_new, finding_24 = self.copy_and_reset_finding(id=24)
        finding_new.title = 'new_title'
        finding_new.cve = 999
        finding_new.save(dedupe_option=True)
        self.assert_finding(finding_new, not_pk=24, duplicate=False, not_hash_code=None)

        # now when we change the title and cve back the same as finding_24, it should be marked as duplicate
        # howwever defect dojo does NOT recalculate the hash_code, so it will not mark this finding as duplicate. feature or BUG?
        finding_new.title = finding_24.title
        finding_new.cve = finding_24.cve
        finding_new.save(dedupe_option=True)
        self.assert_finding(finding_new, not_pk=24, duplicate=False, not_hash_code=None)
        return

    def test_case_sensitiveness_hash_code_computation(self):
        # hash_code calculation is case sensitive. feature or BUG?
        finding_new, finding_24 = self.copy_and_reset_finding(id=24)
        finding_new.title = finding_24.title.upper()
        finding_new.save(dedupe_option=True)
        self.assert_finding(finding_new, not_pk=24, duplicate=False, not_hash_code=finding_24.hash_code)

    def test_title_case(self):
        # currentlt the finding.save method applies title casing to the title
        #  'absolutely great title' becomes 'Absolutely Great Title'
        # as this affects deduplication (hash_code computation) we provide a test case here
        # it will fail if someone removes title casing and force them to think about the implications
        # ideally we will switch to case-in-sensitive hash_code computation.
        # this could be a relatively small impact change as saving findings (currently) doesn't recompute the hash_code
        finding_new, finding_24 = self.copy_and_reset_finding(id=24)
        finding_new.title = 'the quick brown fox jumps over the lazy dog'
        finding_new.save(dedupe_option=True)
        self.assertEqual(finding_new.title, 'The Quick Brown Fox Jumps Over the Lazy Dog')

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

        logger.debug('\t' + 'engagement %i: %s', eng.id, eng.name)

    def log_test(self, test):
        if isinstance(test, int):
            test = Test.objects.get(pk=test)

        logger.debug('\t\t' + 'test %i: %s (algo=%s, dynamic=%s)', test.id, test, test.dedupe_algo, test.test_type.dynamic_tool)
        self.log_findings(test.finding_set.all())

    def log_all_products(self):
        for product in Product.objects.all():
            self.log_summary(product=product)

    def log_findings(self, findings):
        if not findings:
            logger.debug('\t\t' + 'no findings')
        else:
            logger.debug('\t\t' + 'findings:')
            for finding in findings:
                logger.debug('\t\t\t{:4.4}'.format(str(finding.id)) + ': "' + '{:20.20}'.format(finding.title) + '": ' + '{:5.5}'.format(finding.severity) + ': act: ' + '{:5.5}'.format(str(finding.active)) +
                        ': ver: ' + '{:5.5}'.format(str(finding.verified)) + ': mit: ' + '{:5.5}'.format(str(finding.is_Mitigated)) +
                        ': dup: ' + '{:5.5}'.format(str(finding.duplicate)) + ': dup_id: ' +
                        ('{:4.4}'.format(str(finding.duplicate_finding.id)) if finding.duplicate_finding else 'None') + ': hash_code: ' + finding.hash_code +
                        ': eps: ' + str(finding.endpoints.count()) + ": notes: " + str([n.id for n in finding.notes.all()]))

        logger.debug('\t\tendpoints')
        for ep in Endpoint.objects.all():
            logger.debug('\t\t\t' + str(ep.id) + ': ' + str(ep))

        logger.debug('\t\t' + 'endpoint statuses')
        for eps in Endpoint_Status.objects.all():
            logger.debug('\t\t\t' + str(eps.id) + ': ' + str(eps))

    def log_summary(self, product=None, engagement=None, test=None):
        if product:
            self.log_product(product)

        if engagement:
            self.log_engagement(engagement)

        if test:
            self.log_test(test)

        if not product and not engagement and not test:
            self.log_all_products()

    def copy_and_reset_finding(self, id):
        org = Finding.objects.get(id=id)
        new = org
        new.pk = None
        new.duplicate = False
        new.duplicate_finding = None
        new.active = True
        new.hash_code = None
        # return unsaved new finding and reloaded existing finding
        return new, Finding.objects.get(id=id)

    def copy_and_reset_finding_add_endpoints(self, id, static=False, dynamic=True):
        finding_new, finding_org = self.copy_and_reset_finding(id=id)
        # remove file_path and line as we now have endpoints
        finding_new.file_path = None
        finding_new.line = None
        finding_new.static_finding = static
        finding_new.dynamic_finding = dynamic
        # first save without dedupe to avoid hash_code calculation to happen without endpoints
        finding_new.save(dedupe_option=False)
        ep1 = Endpoint(product=finding_new.test.engagement.product, finding=finding_new, host="myhost.com", protocol="https")
        ep1.save()
        ep2 = Endpoint(product=finding_new.test.engagement.product, finding=finding_new, host="myhost2.com", protocol="https")
        ep2.save()
        finding_new.endpoints.add(ep1)
        finding_new.endpoints.add(ep2)
        return finding_new, finding_org

    def copy_and_reset_test(self, id):
        org = Test.objects.get(id=id)
        new = org
        new.pk = None
        # return unsaved new finding and reloaded existing finding
        return new, Test.objects.get(id=id)

    def copy_and_reset_engagement(self, id):
        org = Engagement.objects.get(id=id)
        new = org
        new.pk = None
        # return unsaved new finding and reloaded existing finding
        return new, Engagement.objects.get(id=id)

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
            self.assertNotEqual(finding.hash_code, not_hash_code)

    def set_dedupe_inside_engagement(self, deduplication_on_engagement):
        for eng in Engagement.objects.all():
            logger.debug('setting deduplication_on_engagment to %s for %i', str(deduplication_on_engagement), eng.id)
            eng.deduplication_on_engagement = deduplication_on_engagement
            eng.save()

    def create_new_test_and_engagment_from_finding(self, finding):
        eng_new, eng = self.copy_and_reset_engagement(id=finding.test.engagement.id)
        eng_new.save()
        test_new, test = self.copy_and_reset_test(id=finding.test.id)
        test_new.engagement = eng_new
        test_new.save()
        return test_new, eng_new


# TODO unique id, different test type
# TODO create testutils or basetest class with utility methods
