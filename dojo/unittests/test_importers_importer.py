import datetime

from django.test import TestCase
from django.test.utils import override_settings
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient
from dojo.importers.importer.importer import DojoDefaultImporter as Importer
from dojo.importers.reimporter.utils import ENGAGEMENT_NAME_AUTO, PRODUCT_TYPE_NAME_AUTO
from dojo.models import Development_Environment, Engagement, Product, Product_Type, Test, User
from dojo.tools.factory import get_parser
from dojo.tools.sarif.parser import SarifParser
from dojo.tools.gitlab_sast.parser import GitlabSastParser
from dojo.unittests.dojo_test_case import DojoAPITestCase
from dojo.unittests.test_utils import assertImportModelsCreated
import logging


logger = logging.getLogger(__name__)

NPM_AUDIT_NO_VULN_FILENAME = 'dojo/unittests/scans/npm_audit_sample/no_vuln.json'
NPM_AUDIT_SCAN_TYPE = 'NPM Audit Scan'

ENGAGEMENT_NAME_DEFAULT = 'Engagement 1'
ENGAGEMENT_NAME_NEW = 'Engagement New 1'

PRODUCT_NAME_DEFAULT = 'Product A'
PRODUCT_NAME_NEW = 'Product New A'

PRODUCT_TYPE_NAME_DEFAULT = 'Product Type X'


class TestDojoDefaultImporter(TestCase):
    def test_parse_findings(self):
        scan_type = "Acunetix Scan"
        scan = open("dojo/unittests/scans/acunetix/one_finding.xml")

        user, created = User.objects.get_or_create(username="admin")

        product_type, created = Product_Type.objects.get_or_create(name="test")
        product, created = Product.objects.get_or_create(
            name="TestDojoDefaultImporter",
            prod_type=product_type,
        )

        engagement_name = "Test Create Engagement"
        engagement, created = Engagement.objects.get_or_create(
            name=engagement_name,
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        lead = None
        environment = None

        # boot
        importer = Importer()

        # create the test
        # by defaut test_type == scan_type
        test = importer.create_test(scan_type, scan_type, engagement, lead, environment)

        # parse the findings
        parser = get_parser(scan_type)
        parsed_findings = parser.get_findings(scan, test)

        # process
        minimum_severity = "Info"
        active = True
        verified = True
        new_findings = importer.process_parsed_findings(
            test,
            parsed_findings,
            scan_type,
            user,
            active,
            verified,
            minimum_severity=minimum_severity,
        )

        for finding in new_findings:
            self.assertIn(finding.numerical_severity, ["S0", "S1", "S2", "S3", "S4"])

    def test_import_scan(self):
        scan = open("dojo/unittests/scans/sarif/spotbugs.sarif")
        scan_type = SarifParser().get_scan_types()[0]  # SARIF format implement the new method

        user, _ = User.objects.get_or_create(username="admin")
        user_reporter, _ = User.objects.get_or_create(username="user_reporter")

        product_type, _ = Product_Type.objects.get_or_create(name="test2")
        product, _ = Product.objects.get_or_create(
            name="TestDojoDefaultImporter2",
            prod_type=product_type,
        )

        engagement, _ = Engagement.objects.get_or_create(
            name="Test Create Engagement2",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

        importer = Importer()
        scan_date = timezone.make_aware(datetime.datetime(2021, 9, 1), timezone.get_default_timezone())
        test, len_new_findings, len_closed_findings = importer.import_scan(scan, scan_type, engagement, lead=None, environment=None,
                    active=True, verified=True, tags=None, minimum_severity=None,
                    user=user, endpoints_to_add=None, scan_date=scan_date, version=None, branch_tag=None, build_id=None,
                    commit_hash=None, push_to_jira=None, close_old_findings=False, group_by=None, api_scan_configuration=None)

        self.assertEqual(f"SpotBugs Scan ({scan_type})", test.test_type.name)
        self.assertEqual(56, len_new_findings)
        self.assertEqual(0, len_closed_findings)

    def test_import_scan_without_test_scan_type(self):
        # GitLabSastParser implements get_tests but report has no scanner name
        scan = open("dojo/unittests/scans/gitlab_sast/gl-sast-report-1-vuln.json")
        scan_type = GitlabSastParser().get_scan_types()[0]

        user, _ = User.objects.get_or_create(username="admin")
        user_reporter, _ = User.objects.get_or_create(username="user_reporter")

        product_type, _ = Product_Type.objects.get_or_create(name="test2")
        product, _ = Product.objects.get_or_create(
            name="TestDojoDefaultImporter2",
            prod_type=product_type,
        )

        engagement, _ = Engagement.objects.get_or_create(
            name="Test Create Engagement2",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

        importer = Importer()
        scan_date = timezone.make_aware(datetime.datetime(2021, 9, 1), timezone.get_default_timezone())
        test, len_new_findings, len_closed_findings = importer.import_scan(scan, scan_type, engagement, lead=None, environment=None,
                    active=True, verified=True, tags=None, minimum_severity=None,
                    user=user, endpoints_to_add=None, scan_date=scan_date, version=None, branch_tag=None, build_id=None,
                    commit_hash=None, push_to_jira=None, close_old_findings=False, group_by=None, api_scan_configuration=None)

        self.assertEqual("GitLab SAST Report", test.test_type.name)
        self.assertEqual(1, len_new_findings)
        self.assertEqual(0, len_closed_findings)


@override_settings(TRACK_IMPORT_HISTORY=True)
class FlexibleImportReimportTestAPI(DojoAPITestCase):
    def __init__(self, *args, **kwargs):
        # TODO remove __init__ if it does nothing...
        DojoAPITestCase.__init__(self, *args, **kwargs)
        # super(ImportReimportMixin, self).__init__(*args, **kwargs)
        # super(DojoAPITestCase, self).__init__(*args, **kwargs)
        super().__init__(*args, **kwargs)

    def setUp(self):
        testuser, _ = User.objects.get_or_create(username="admin", is_superuser=True)
        # testuser = User.objects.get(username='admin')
        token, _ = Token.objects.get_or_create(user=testuser)
        self.client = APIClient(raise_request_exception=True)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
        self.create_default_data()
        # self.url = reverse(self.viewname + '-list')

    def create_default_data(self):
        # creating is much faster compare to using a fixture
        logger.debug('creating default product + engagement')
        Development_Environment.objects.get_or_create(name='Development')
        self.product_type = self.create_product_type(PRODUCT_TYPE_NAME_DEFAULT)
        self.product = self.create_product(PRODUCT_NAME_DEFAULT)
        self.engagement = self.create_engagement(ENGAGEMENT_NAME_DEFAULT, product=self.product)

    def test_import_by_engagement_id(self):
        # import into engagement should result in 1 new Test object created
        with assertImportModelsCreated(self, tests=1, engagements=0, products=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, engagement=self.engagement.id)

    def test_import_by_product_id_engagement_name_exists(self):
        # import into product should result in 1 new Test object created, engagement already exists
        with assertImportModelsCreated(self, tests=1, engagements=0, products=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product=self.product.id,
                engagement=None, engagement_name=ENGAGEMENT_NAME_DEFAULT)
            test_id = import0['test']
            self.assertEqual(Test.objects.get(id=test_id).engagement, self.engagement)

    def test_import_by_product_id_engagement_name_not_exists(self):
        # import into product should result in 1 new Engagement object created as it doesn't exist yet
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product=self.product.id,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, expected_http_status_code=400)

    def test_import_by_product_id_only_engagement_exists(self):
        self.engagement = self.create_engagement(ENGAGEMENT_NAME_AUTO, self.product)
        with assertImportModelsCreated(self, tests=1, engagements=0, products=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product=self.product.id,
                 engagement=None)
            test_id = import0['test']
            self.assertEqual(Test.objects.get(id=test_id).engagement.id, self.engagement.id)

    def test_import_by_product_id_only_engagement_not_exists(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product=self.product.id,
                engagement=None, expected_http_status_code=400)

    def test_import_by_product_name_exists_engagement_name_exists(self):
        with assertImportModelsCreated(self, tests=1, engagements=0, products=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_DEFAULT)
            test_id = import0['test']
            self.assertEqual(Test.objects.get(id=test_id).engagement, self.engagement)

    def test_import_by_product_name_exists_engagement_name_not_exists(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, expected_http_status_code=400)

    def test_import_by_product_name_only_exists_engagement_exists(self):
        self.engagement = self.create_engagement(ENGAGEMENT_NAME_AUTO, self.product)
        with assertImportModelsCreated(self, tests=1, engagements=0, products=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_DEFAULT,
                engagement=None)
            test_id = import0['test']
            self.assertEqual(Test.objects.get(id=test_id).engagement, self.engagement)

    def test_import_by_product_name_only_exists_engagement_not_exists(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, expected_http_status_code=400)

    def test_import_by_product_name_not_exists_engagement_name(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, expected_http_status_code=400)

    def test_import_by_product_name_and_product_type_id(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                product_type=self.product_type.id, engagement=None, expected_http_status_code=400)

    def test_import_by_product_name_and_product_type_name_exists(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                product_type_name=PRODUCT_TYPE_NAME_DEFAULT, engagement=None, expected_http_status_code=400)

    def test_import_by_product_name_and_product_type_name_not_exists(self):
        # no permission to crete new product_type by name
        import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
            product_type_name='bla bla', engagement=None, expected_http_status_code=403)

    def test_import_by_product_name_only_not_exists(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                engagement=None, expected_http_status_code=400)

    def test_import_by_engagement_id_auto_create(self):
        # import into engagement should result in 1 new Test object created
        with assertImportModelsCreated(self, tests=1, engagements=0, products=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, engagement=self.engagement.id,
                auto_create_engagement=True, auto_create_product=True)

    def test_import_by_product_id_engagement_name_exists_auto_create(self):
        # import into product should result in 1 new Test object created, engagement already exists
        with assertImportModelsCreated(self, tests=1, engagements=0, products=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product=self.product.id,
                engagement=None, engagement_name=ENGAGEMENT_NAME_DEFAULT, auto_create_engagement=True, auto_create_product=True)
            test_id = import0['test']
            self.assertEqual(Test.objects.get(id=test_id).engagement, self.engagement)

    def test_import_by_product_id_engagement_name_not_exists_auto_create(self):
        # import into product should result in 1 new Engagement object created as it doesn't exist yet
        with assertImportModelsCreated(self, tests=1, engagements=1, products=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product=self.product.id,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, auto_create_engagement=True, auto_create_product=True)
            engagement_new = self.get_latest_model(Engagement)
            self.assertEqual(engagement_new.name, ENGAGEMENT_NAME_NEW)
            test_id = import0['test']
            self.assertEqual(Test.objects.get(id=test_id).engagement, engagement_new)
            self.assertEqual(engagement_new.product, self.product)

    def test_import_by_product_id_only_engagement_exists_auto_create(self):
        self.engagement = self.create_engagement(ENGAGEMENT_NAME_AUTO, self.product)
        with assertImportModelsCreated(self, tests=1, engagements=0, products=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product=self.product.id,
                engagement=None, auto_create_engagement=True, auto_create_product=True)
            test_id = import0['test']
            self.assertEqual(Test.objects.get(id=test_id).engagement.id, self.engagement.id)

    def test_import_by_product_id_only_engagement_not_exists_auto_create(self):
        with assertImportModelsCreated(self, tests=1, engagements=1, products=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product=self.product.id,
                engagement=None, auto_create_engagement=True, auto_create_product=True)
            engagement_new = self.get_latest_model(Engagement)
            self.assertTrue(engagement_new.name.startswith(ENGAGEMENT_NAME_AUTO + ' - '), msg='{} doesn''t start with {}'.format(engagement_new.name, ENGAGEMENT_NAME_AUTO + ' - '))
            test_id = import0['test']
            self.assertEqual(Test.objects.get(id=test_id).engagement, engagement_new)
            self.assertEqual(engagement_new.product, self.product)

            # TODO: VS: Add case with invalid product id

    def test_import_by_product_name_exists_engagement_name_exists_auto_create(self):
        with assertImportModelsCreated(self, tests=1, engagements=0, products=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_DEFAULT, auto_create_engagement=True, auto_create_product=True)
            test_id = import0['test']
            self.assertEqual(Test.objects.get(id=test_id).engagement, self.engagement)

    def test_import_by_product_name_exists_engagement_name_not_exists_auto_create(self):
        with assertImportModelsCreated(self, tests=1, engagements=1, products=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, auto_create_engagement=True, auto_create_product=True)
            engagement_new = self.get_latest_model(Engagement)
            self.assertEqual(engagement_new.name, ENGAGEMENT_NAME_NEW)
            test_id = import0['test']
            self.assertEqual(Test.objects.get(id=test_id).engagement, engagement_new)
            self.assertEqual(engagement_new.product, self.product)

    def test_import_by_product_name_only_exists_engagement_exists_auto_create(self):
        self.engagement = self.create_engagement(ENGAGEMENT_NAME_AUTO, self.product)
        with assertImportModelsCreated(self, tests=1, engagements=0, products=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, auto_create_engagement=True, auto_create_product=True)
            test_id = import0['test']
            self.assertEqual(Test.objects.get(id=test_id).engagement, self.engagement)

    def test_import_by_product_name_only_exists_engagement_not_exists_auto_create(self):
        with assertImportModelsCreated(self, tests=1, engagements=1, products=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, auto_create_engagement=True, auto_create_product=True)
            engagement_new = self.get_latest_model(Engagement)
            self.assertTrue(engagement_new.name.startswith(ENGAGEMENT_NAME_AUTO + ' - '), msg='{} doesn''t start with {}'.format(engagement_new.name, ENGAGEMENT_NAME_AUTO + ' - '))
            test_id = import0['test']
            self.assertEqual(Test.objects.get(id=test_id).engagement, engagement_new)
            self.assertEqual(engagement_new.product, self.product)

    def test_import_by_product_name_not_exists_engagement_name_auto_create(self):
        with assertImportModelsCreated(self, tests=1, engagements=1, products=1):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, auto_create_engagement=True, auto_create_product=True)
            product = Product.objects.last()
            self.assertEqual(product.name, PRODUCT_NAME_NEW)
            engagement_new = self.get_latest_model(Engagement)
            self.assertEqual(engagement_new.name, ENGAGEMENT_NAME_NEW)
            test_id = import0['test']
            self.assertEqual(Test.objects.get(id=test_id).engagement, engagement_new)
            self.assertEqual(engagement_new.product, product)

    def test_import_by_product_name_and_product_type_id_auto_create(self):
        with assertImportModelsCreated(self, tests=1, engagements=1, products=1):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                product_type=self.product_type.id, engagement=None, auto_create_engagement=True, auto_create_product=True)
            product = Product.objects.last()
            self.assertEqual(product.name, PRODUCT_NAME_NEW)
            self.assertEqual(product.prod_type.name, PRODUCT_TYPE_NAME_DEFAULT)

            engagement_new = self.get_latest_model(Engagement)
            self.assertTrue(engagement_new.name.startswith(ENGAGEMENT_NAME_AUTO + ' - '),
                msg='{} doesn''t start with {}'.format(engagement_new.name, ENGAGEMENT_NAME_AUTO + ' - '))
            test_id = import0['test']
            self.assertEqual(Test.objects.get(id=test_id).engagement, engagement_new)
            self.assertEqual(engagement_new.product, product)

            # TODO: VS: Add case with invalid product_type id

    def test_import_by_product_name_and_product_type_name_exists_auto_create(self):
        with assertImportModelsCreated(self, tests=1, engagements=1, products=1):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                product_type_name=PRODUCT_TYPE_NAME_DEFAULT, engagement=None, auto_create_engagement=True, auto_create_product=True)
            product = Product.objects.last()
            self.assertEqual(product.name, PRODUCT_NAME_NEW)
            self.assertEqual(product.prod_type.name, PRODUCT_TYPE_NAME_DEFAULT)

            engagement_new = self.get_latest_model(Engagement)
            self.assertTrue(engagement_new.name.startswith(ENGAGEMENT_NAME_AUTO + ' - '),
                msg='{} doesn''t start with {}'.format(engagement_new.name, ENGAGEMENT_NAME_AUTO + ' - '))
            test_id = import0['test']
            self.assertEqual(Test.objects.get(id=test_id).engagement, engagement_new)
            self.assertEqual(engagement_new.product, product)

    def test_import_by_product_name_and_product_type_name_not_exists_auto_create(self):
        # no permission to crete new product_type by name
        import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
            product_type_name='bla bla', engagement=None, auto_create_engagement=True, auto_create_product=True, expected_http_status_code=403)

    def test_import_by_product_name_only_not_exists_auto_create(self):
        with assertImportModelsCreated(self, tests=1, engagements=1, products=1):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                engagement=None, auto_create_engagement=True, auto_create_product=True)
            product = Product.objects.last()
            self.assertEqual(product.name, PRODUCT_NAME_NEW)
            engagement_new = self.get_latest_model(Engagement)
            self.assertTrue(engagement_new.name.startswith(ENGAGEMENT_NAME_AUTO + ' - '),
                msg='{} doesn''t start with {}'.format(engagement_new.name, ENGAGEMENT_NAME_AUTO + ' - '))
            test_id = import0['test']
            self.assertEqual(Test.objects.get(id=test_id).engagement, engagement_new)
            self.assertEqual(engagement_new.product, product)
            self.assertEqual(engagement_new.product.prod_type.name, PRODUCT_TYPE_NAME_AUTO)

    def test_import_with_invalid_parameters(self):
        with self.subTest('no parameters'):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, expected_http_status_code=400)

        with self.subTest('no product data'):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, engagement_name='what the bleep', expected_http_status_code=400)

        with self.subTest('invalid product'):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, product=67283, expected_http_status_code=400)

        with self.subTest('invalid engagement'):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=1254235, expected_http_status_code=400)

        with self.subTest('invalid engagement, but exists in another product'):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement_name=ENGAGEMENT_NAME_DEFAULT, product_name='blabla', expected_http_status_code=400)

        with self.subTest('invalid engagement not id'):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement='bla bla', expected_http_status_code=400)

        with self.subTest('invalid product not id'):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                product='bla bla', expected_http_status_code=400)

        with self.subTest('invalid product_type not id'):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
            product_type='bla bla', expected_http_status_code=400)


# TODO Authz test cases
# TODO Reimport
