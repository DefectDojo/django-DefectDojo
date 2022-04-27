from unittest.mock import patch
import uuid
from .dojo_test_case import DojoTestCase, get_unit_tests_path
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient
from dojo.importers.importer.importer import DojoDefaultImporter as Importer
from dojo.models import Development_Environment, Engagement, Finding, Product, Product_Type, Test, User
from dojo.tools.factory import get_parser
from dojo.tools.sarif.parser import SarifParser
from dojo.tools.gitlab_sast.parser import GitlabSastParser
from .dojo_test_case import DojoAPITestCase
from .test_utils import assertImportModelsCreated
import logging
from dojo.importers.utils import handle_vulnerability_ids

from dojo.utils import get_object_or_none


logger = logging.getLogger(__name__)

NPM_AUDIT_NO_VULN_FILENAME = 'scans/npm_audit_sample/no_vuln.json'
NPM_AUDIT_SCAN_TYPE = 'NPM Audit Scan'

ACUNETIX_AUDIT_ONE_VULN_FILENAME = 'scans/acunetix/one_finding.xml'
ENDPOINT_META_IMPORTER_FILENAME = 'endpoint_meta_import/no_endpoint_meta_import.csv'

ENGAGEMENT_NAME_DEFAULT = 'Engagement 1'
ENGAGEMENT_NAME_NEW = 'Engagement New 1'

PRODUCT_NAME_DEFAULT = 'Product A'
PRODUCT_NAME_NEW = 'Product New A'

PRODUCT_TYPE_NAME_DEFAULT = 'Shiny Products'
PRODUCT_TYPE_NAME_NEW = 'Extra Shiny Products'

TEST_TITLE_DEFAULT = 'super important scan'
TEST_TITLE_ALTERNATE = 'meh import scan'
TEST_TITLE_NEW = 'lol importing via reimport'


class TestDojoDefaultImporter(DojoTestCase):
    def test_parse_findings(self):
        scan_type = "Acunetix Scan"
        scan = open(get_unit_tests_path() + "/scans/acunetix/one_finding.xml")

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
        lead, _ = User.objects.get_or_create(username="admin")
        environment, _ = Development_Environment.objects.get_or_create(name="Development")

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
        scan_date = None
        new_findings = importer.process_parsed_findings(
            test,
            parsed_findings,
            scan_type,
            user,
            active,
            verified,
            minimum_severity=minimum_severity,
            scan_date=scan_date,
            sync=True
        )

        for finding in new_findings:
            self.assertIn(finding.numerical_severity, ["S0", "S1", "S2", "S3", "S4"])

    def test_import_scan(self):
        scan = open(get_unit_tests_path() + "/scans/sarif/spotbugs.sarif")
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
        scan_date = None
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        test, len_new_findings, len_closed_findings, _ = importer.import_scan(scan, scan_type, engagement, lead=None, environment=environment,
                    active=True, verified=True, tags=None, minimum_severity=None,
                    user=user, endpoints_to_add=None, scan_date=scan_date, version=None, branch_tag=None, build_id=None,
                    commit_hash=None, push_to_jira=None, close_old_findings=False, group_by=None, api_scan_configuration=None)

        self.assertEqual(f"SpotBugs Scan ({scan_type})", test.test_type.name)
        self.assertEqual(56, len_new_findings)
        self.assertEqual(0, len_closed_findings)

    def test_import_scan_without_test_scan_type(self):
        # GitLabSastParser implements get_tests but report has no scanner name
        scan = open(get_unit_tests_path() + "/scans/gitlab_sast/gl-sast-report-1-vuln.json")
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
        scan_date = None
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        test, len_new_findings, len_closed_findings, _ = importer.import_scan(scan, scan_type, engagement, lead=None, environment=environment,
                    active=True, verified=True, tags=None, minimum_severity=None,
                    user=user, endpoints_to_add=None, scan_date=scan_date, version=None, branch_tag=None, build_id=None,
                    commit_hash=None, push_to_jira=None, close_old_findings=False, group_by=None, api_scan_configuration=None)

        self.assertEqual("GitLab SAST Report", test.test_type.name)
        self.assertEqual(1, len_new_findings)
        self.assertEqual(0, len_closed_findings)


class FlexibleImportTestAPI(DojoAPITestCase):
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
        # engagement name is not unique by itself and not unique inside a product
        self.engagement_last = self.create_engagement(ENGAGEMENT_NAME_DEFAULT, product=self.product)

    @patch('dojo.jira_link.helper.get_jira_project')
    def test_import_by_engagement_id(self, mock):
        with assertImportModelsCreated(self, tests=1, engagements=0, products=0, product_types=0, endpoints=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, engagement=self.engagement.id, test_title=TEST_TITLE_DEFAULT)
            test_id = import0['test']
            self.assertEqual(get_object_or_none(Test, id=test_id).title, TEST_TITLE_DEFAULT)
            self.assertEqual(import0['engagement_id'], self.engagement.id)
            self.assertEqual(import0['product_id'], self.engagement.product.id)
        mock.assert_called_with(self.engagement)

    @patch('dojo.jira_link.helper.get_jira_project')
    def test_import_by_product_name_exists_engagement_name_exists(self, mock):
        with assertImportModelsCreated(self, tests=1, engagements=0, products=0, product_types=0, endpoints=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_DEFAULT)
            test_id = import0['test']
            self.assertEqual(Test.objects.get(id=test_id).engagement, self.engagement_last)
            self.assertEqual(import0['engagement_id'], self.engagement_last.id)
            self.assertEqual(import0['product_id'], self.engagement_last.product.id)
        mock.assert_called_with(self.engagement_last)

    def test_import_by_product_name_exists_engagement_name_not_exists(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, product_types=0, endpoints=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, expected_http_status_code=400)

    @patch('dojo.jira_link.helper.get_jira_project')
    def test_import_by_product_name_exists_engagement_name_not_exists_auto_create(self, mock):
        mock.return_value = None
        with assertImportModelsCreated(self, tests=1, engagements=1, products=0, product_types=0, endpoints=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, auto_create_context=True)
            test_id = import0['test']
            self.assertEqual(get_object_or_none(Test, id=test_id).title, None)
            self.assertEqual(get_object_or_none(Engagement, id=import0['engagement_id']).name, ENGAGEMENT_NAME_NEW)
            self.assertEqual(import0['product_id'], self.engagement.product.id)
        # the new engagement should inherit the jira settings from the product
        # the jira settings are retrieved before an engagement is auto created
        mock.assert_called_with(self.product)

    def test_import_by_product_name_not_exists_engagement_name(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, product_types=0, endpoints=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, expected_http_status_code=400)

    @patch('dojo.jira_link.helper.get_jira_project')
    def test_import_by_product_name_not_exists_engagement_name_auto_create(self, mock):
        with assertImportModelsCreated(self, tests=1, engagements=1, products=1, product_types=0, endpoints=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, product_type_name=PRODUCT_TYPE_NAME_DEFAULT, auto_create_context=True)
            test_id = import0['test']
            self.assertEqual(get_object_or_none(Test, id=test_id).title, None)
            self.assertEqual(get_object_or_none(Engagement, id=import0['engagement_id']).name, ENGAGEMENT_NAME_NEW)
            self.assertEqual(get_object_or_none(Product, id=import0['product_id']).name, PRODUCT_NAME_NEW)
            self.assertEqual(get_object_or_none(Product, id=import0['product_id']).prod_type.name, PRODUCT_TYPE_NAME_DEFAULT)

        mock.assert_not_called()

    @patch('dojo.jira_link.helper.get_jira_project')
    def test_import_by_product_type_name_not_exists_product_name_not_exists_engagement_name_auto_create(self, mock):
        with assertImportModelsCreated(self, tests=1, engagements=1, products=1, product_types=1, endpoints=0):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, product_type_name=PRODUCT_TYPE_NAME_NEW, auto_create_context=True)
            test_id = import0['test']
            self.assertEqual(get_object_or_none(Test, id=test_id).title, None)
            self.assertEqual(get_object_or_none(Engagement, id=import0['engagement_id']).name, ENGAGEMENT_NAME_NEW)
            self.assertEqual(get_object_or_none(Product, id=import0['product_id']).name, PRODUCT_NAME_NEW)
            self.assertEqual(get_object_or_none(Product, id=import0['product_id']).prod_type.name, PRODUCT_TYPE_NAME_NEW)
            self.assertEqual(get_object_or_none(Product_Type, id=import0['product_type_id']).name, PRODUCT_TYPE_NAME_NEW)

        mock.assert_not_called()

    def test_endpoint_meta_import_by_product_name_exists(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, endpoints=0):
            import0 = self.endpoint_meta_import_scan_with_params(ENDPOINT_META_IMPORTER_FILENAME, product=None, product_name=PRODUCT_NAME_DEFAULT, expected_http_status_code=201)

    def test_endpoint_meta_import_by_product_name_not_exists(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, endpoints=0):
            import0 = self.endpoint_meta_import_scan_with_params(ENDPOINT_META_IMPORTER_FILENAME, product=None, product_name=PRODUCT_NAME_NEW, expected_http_status_code=400)

    def test_import_with_invalid_parameters(self):
        with self.subTest('scan_date in the future'):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, product_type_name=PRODUCT_TYPE_NAME_NEW, auto_create_context=True, scan_date='2222-01-01',
                expected_http_status_code=400)

        with self.subTest('no parameters'):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, expected_http_status_code=400)
            self.assertEqual(import0, ['product_name parameter missing'])

        with self.subTest('no product data'):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, engagement_name='what the bleep', expected_http_status_code=400)
            self.assertEqual(import0, ['product_name parameter missing'])

        with self.subTest('engagement_name missing'):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, product_name='67283', expected_http_status_code=400)
            self.assertEqual(import0, ['engagement_name parameter missing'])

        with self.subTest('invalid product type'):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, product_type_name='valentijn', product_name='67283', engagement_name='valentijn', expected_http_status_code=400)
            self.assertEqual(import0, ["Product Type 'valentijn' doesn't exist"])

        with self.subTest('invalid product'):
            # random product type to avoid collision with other tests
            another_product_type_name = str(uuid.uuid4())
            Product_Type.objects.create(name=another_product_type_name)
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, product_type_name=another_product_type_name, product_name=PRODUCT_NAME_DEFAULT, engagement_name='valentijn', expected_http_status_code=400)
            self.assertEqual(import0, ["Product '%s' doesn't exist in Product_Type '%s'" % (PRODUCT_NAME_DEFAULT, another_product_type_name)])

        with self.subTest('invalid engagement'):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=1254235, expected_http_status_code=400)
            self.assertEqual(import0, ["Engagement '1254235' doesn''t exist"])

        with self.subTest('invalid engagement, but exists in another product'):
            # random product to avoid collision with other tests
            another_product_name = str(uuid.uuid4())
            self.product = self.create_product(another_product_name)
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, engagement=None,
                engagement_name=ENGAGEMENT_NAME_DEFAULT, product_name=another_product_name, expected_http_status_code=400)
            self.assertEqual(import0, ["Engagement 'Engagement 1' doesn't exist in Product '%s'" % another_product_name])

        with self.subTest('invalid engagement not id'):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement='bla bla', expected_http_status_code=400)
            self.assertEqual(import0, ['engagement must be an integer'])

        with self.subTest('autocreate product but no product type name'):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, auto_create_context=True, expected_http_status_code=400)
            self.assertEqual(import0, ["Product '%s' doesn't exist and no product_type_name provided to create the new product in" % PRODUCT_NAME_NEW])

        with self.subTest('autocreate engagement but no product_name'):
            import0 = self.import_scan_with_params(NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=None,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, auto_create_context=True, expected_http_status_code=400)
            self.assertEqual(import0, ['product_name parameter missing'])


class FlexibleReimportTestAPI(DojoAPITestCase):
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
        self.test = self.create_test(engagement=self.engagement, scan_type=NPM_AUDIT_SCAN_TYPE, title=TEST_TITLE_DEFAULT)
        # self.test = self.create_test(engagement=self.engagement, scan_type=NPM_AUDIT_SCAN_TYPE)
        # test title is not unique inside engagements
        self.test_last_by_title = self.create_test(engagement=self.engagement, scan_type=NPM_AUDIT_SCAN_TYPE, title=TEST_TITLE_DEFAULT)
        self.test_with_title = self.create_test(engagement=self.engagement, scan_type=NPM_AUDIT_SCAN_TYPE, title=TEST_TITLE_ALTERNATE)
        self.test_last_by_scan_type = self.create_test(engagement=self.engagement, scan_type=NPM_AUDIT_SCAN_TYPE)

    def test_reimport_by_test_id(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, product_types=0, endpoints=0):
            import0 = self.reimport_scan_with_params(self.test.id, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE)
            test_id = import0['test']
            self.assertEqual(get_object_or_none(Test, id=test_id).title, TEST_TITLE_DEFAULT)
            self.assertEqual(test_id, self.test.id)
            self.assertEqual(import0['engagement_id'], self.test.engagement.id)
            self.assertEqual(import0['product_id'], self.test.engagement.product.id)

    def test_reimport_by_product_name_exists_engagement_name_exists_no_title(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, product_types=0, endpoints=0):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_DEFAULT)
            test_id = import0['test']
            self.assertEqual(test_id, self.test_last_by_scan_type.id)
            self.assertEqual(import0['engagement_id'], self.test_last_by_scan_type.engagement.id)
            self.assertEqual(import0['product_id'], self.test_last_by_scan_type.engagement.product.id)

    def test_reimport_by_product_name_exists_engagement_name_exists_scan_type_not_exsists_test_title_exists(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, product_types=0, endpoints=0):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type='Acunetix Scan', product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_DEFAULT, test_title=TEST_TITLE_DEFAULT, expected_http_status_code=400)

    @patch('dojo.jira_link.helper.get_jira_project')
    def test_reimport_by_product_name_exists_engagement_name_exists_scan_type_not_exsists_test_title_exists_auto_create(self, mock):
        with assertImportModelsCreated(self, tests=1, engagements=0, products=0, product_types=0, endpoints=1):
            import0 = self.reimport_scan_with_params(None, ACUNETIX_AUDIT_ONE_VULN_FILENAME, scan_type='Acunetix Scan', product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_DEFAULT, test_title=TEST_TITLE_DEFAULT, auto_create_context=True)
            test_id = import0['test']
            self.assertEqual(get_object_or_none(Test, id=test_id).title, TEST_TITLE_DEFAULT)
            self.assertEqual(import0['engagement_id'], self.engagement.id)
        mock.assert_called_with(self.engagement)

    def test_reimport_by_product_name_exists_engagement_name_exists_scan_type_not_exsists_test_title_not_exists(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, product_types=0, endpoints=0):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type='Acunetix Scan', product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_DEFAULT, test_title='bogus title', expected_http_status_code=400)

    @patch('dojo.jira_link.helper.get_jira_project')
    def test_reimport_by_product_name_exists_engagement_name_exists_scan_type_not_exsists_test_title_not_exists_auto_create(self, mock):
        with assertImportModelsCreated(self, tests=1, engagements=0, products=0, product_types=0, endpoints=1):
            import0 = self.reimport_scan_with_params(None, ACUNETIX_AUDIT_ONE_VULN_FILENAME, scan_type='Acunetix Scan', product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_DEFAULT, test_title='bogus title', auto_create_context=True)
            test_id = import0['test']
            self.assertEqual(get_object_or_none(Test, id=test_id).scan_type, 'Acunetix Scan')
            self.assertEqual(get_object_or_none(Test, id=test_id).title, 'bogus title')
            self.assertEqual(import0['engagement_id'], self.engagement.id)
        # the new test should inherit the jira settings from the engagement
        # the jira settings are retrieved before an test is auto created
        mock.assert_called_with(self.engagement)

    def test_reimport_by_product_name_exists_engagement_name_exists_test_title_exists(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, product_types=0, endpoints=0):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_DEFAULT, test_title=TEST_TITLE_DEFAULT)
            test_id = import0['test']
            self.assertEqual(test_id, self.test_last_by_title.id)

    def test_reimport_by_product_name_exists_engagement_name_not_exists(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, product_types=0, endpoints=0):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, expected_http_status_code=400)

    @patch('dojo.jira_link.helper.get_jira_project')
    def test_reimport_by_product_name_exists_engagement_name_not_exists_auto_create(self, mock):
        with assertImportModelsCreated(self, tests=1, engagements=1, products=0, product_types=0, endpoints=0):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_DEFAULT,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, auto_create_context=True)
            test_id = import0['test']
            self.assertEqual(get_object_or_none(Test, id=test_id).title, None)
            self.assertEqual(get_object_or_none(Engagement, id=import0['engagement_id']).name, ENGAGEMENT_NAME_NEW)
            self.assertEqual(import0['product_id'], self.engagement.product.id)
            self.assertEqual(import0['product_type_id'], self.engagement.product.prod_type.id)
        # the new engagement should inherit the jira settings from the product
        # the jira settings are retrieved before an engagement is auto created
        mock.assert_called_with(self.product)

    def test_reimport_by_product_name_not_exists_engagement_name(self):
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, product_types=0, endpoints=0):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, expected_http_status_code=400)

    @patch('dojo.jira_link.helper.get_jira_project')
    def test_reimport_by_product_name_not_exists_engagement_name_auto_create(self, mock):
        with assertImportModelsCreated(self, tests=1, engagements=1, products=1, product_types=0, endpoints=0):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, product_type_name=PRODUCT_TYPE_NAME_DEFAULT, auto_create_context=True)
            test_id = import0['test']
            self.assertEqual(get_object_or_none(Test, id=test_id).title, None)
            self.assertEqual(get_object_or_none(Engagement, id=import0['engagement_id']).name, ENGAGEMENT_NAME_NEW)
            self.assertEqual(get_object_or_none(Product, id=import0['product_id']).name, PRODUCT_NAME_NEW)
            self.assertEqual(get_object_or_none(Product, id=import0['product_id']).prod_type.name, PRODUCT_TYPE_NAME_DEFAULT)

        mock.assert_not_called()

    @patch('dojo.jira_link.helper.get_jira_project')
    def test_reimport_by_product_type_not_exists_product_name_not_exists_engagement_name_auto_create(self, mock):
        with assertImportModelsCreated(self, tests=1, engagements=1, products=1, product_types=1, endpoints=0):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, product_type_name=PRODUCT_TYPE_NAME_NEW, auto_create_context=True)
            test_id = import0['test']
            self.assertEqual(get_object_or_none(Test, id=test_id).title, None)
            self.assertEqual(get_object_or_none(Engagement, id=import0['engagement_id']).name, ENGAGEMENT_NAME_NEW)
            self.assertEqual(get_object_or_none(Product, id=import0['product_id']).name, PRODUCT_NAME_NEW)
            self.assertEqual(get_object_or_none(Product, id=import0['product_id']).prod_type.name, PRODUCT_TYPE_NAME_NEW)

        mock.assert_not_called()

    def test_reimport_with_invalid_parameters(self):
        with self.subTest('scan_date in the future'):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE, product_name=PRODUCT_NAME_NEW,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, product_type_name=PRODUCT_TYPE_NAME_NEW, auto_create_context=True, scan_date='2222-01-01',
                expected_http_status_code=400)

        with self.subTest('no parameters'):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, expected_http_status_code=400)
            self.assertEqual(import0, ['product_name parameter missing'])

        with self.subTest('no product data'):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, engagement_name='what the bleep', expected_http_status_code=400)
            self.assertEqual(import0, ['product_name parameter missing'])

        with self.subTest('non engagement_name'):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, product_name='67283', expected_http_status_code=400)
            self.assertEqual(import0, ['engagement_name parameter missing'])

        with self.subTest('invalid product type'):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, product_type_name='valentijn', product_name='67283', engagement_name='valentijn', expected_http_status_code=400)
            self.assertEqual(import0, ["Product Type 'valentijn' doesn't exist"])

        with self.subTest('invalid product'):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, product_name='67283', engagement_name='valentijn', expected_http_status_code=400)
            self.assertEqual(import0, ["Product '67283' doesn't exist"])

        with self.subTest('valid product, but other product type'):
            # random product type to avoid collision with other tests
            another_product_type_name = str(uuid.uuid4())
            Product_Type.objects.create(name=another_product_type_name)

            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, product_type_name=another_product_type_name, product_name=PRODUCT_NAME_DEFAULT, engagement_name='valentijn', expected_http_status_code=400)
            self.assertEqual(import0, ["Product '%s' doesn't exist in Product_Type '%s'" % (PRODUCT_NAME_DEFAULT, another_product_type_name)])

        with self.subTest('invalid engagement'):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=1254235, expected_http_status_code=400)
            self.assertEqual(import0, ['product_name parameter missing'])

        with self.subTest('invalid engagement, but exists in another product'):
            # random product to avoid collision with other tests
            another_product_name = str(uuid.uuid4())
            self.product = self.create_product(another_product_name)
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement_name=ENGAGEMENT_NAME_DEFAULT, product_name=another_product_name, expected_http_status_code=400)
            self.assertEqual(import0, ["Engagement 'Engagement 1' doesn't exist in Product '%s'" % another_product_name])

        with self.subTest('invalid engagement not id'):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement='bla bla', expected_http_status_code=400)
            self.assertEqual(import0, ['engagement must be an integer'])

        with self.subTest('autocreate product but no product type name'):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                product_name=PRODUCT_NAME_NEW, engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, auto_create_context=True, expected_http_status_code=400)
            self.assertEqual(import0, ["Product '%s' doesn't exist and no product_type_name provided to create the new product in" % PRODUCT_NAME_NEW])

        with self.subTest('autocreate engagement but no product_name'):
            import0 = self.reimport_scan_with_params(None, NPM_AUDIT_NO_VULN_FILENAME, scan_type=NPM_AUDIT_SCAN_TYPE,
                engagement=None, engagement_name=ENGAGEMENT_NAME_NEW, auto_create_context=True, expected_http_status_code=400)
            self.assertEqual(import0, ['product_name parameter missing'])


class TestImporterUtils(DojoAPITestCase):
    @patch('dojo.importers.utils.Vulnerability_Id', autospec=True)
    def test_handle_vulnerability_ids_references_and_cve(self, mock):
        finding = Finding()
        finding.cve = 'CVE'
        finding.unsaved_vulnerability_ids = ['REF-1', 'REF-2']

        handle_vulnerability_ids(finding)

        vulnerability_ids = ['CVE', 'REF-1', 'REF-2']

        self.assertEqual(6, len(mock.mock_calls))
        self.assertEqual('CVE', mock.mock_calls[0].kwargs['vulnerability_id'])
        self.assertEqual('CVE', mock.mock_calls[0].kwargs['finding'].cve)
        self.assertEqual(vulnerability_ids, mock.mock_calls[0].kwargs['finding'].unsaved_vulnerability_ids)
        self.assertEqual('REF-1', mock.mock_calls[2].kwargs['vulnerability_id'])
        self.assertEqual('CVE', mock.mock_calls[2].kwargs['finding'].cve)
        self.assertEqual(vulnerability_ids, mock.mock_calls[2].kwargs['finding'].unsaved_vulnerability_ids)
        self.assertEqual('REF-2', mock.mock_calls[4].kwargs['vulnerability_id'])
        self.assertEqual('CVE', mock.mock_calls[4].kwargs['finding'].cve)
        self.assertEqual(vulnerability_ids, mock.mock_calls[2].kwargs['finding'].unsaved_vulnerability_ids)

    @patch('dojo.importers.utils.Vulnerability_Id', autospec=True)
    def test_handle_no_vulnerability_ids_references_and_cve(self, mock):
        finding = Finding()
        finding.cve = 'CVE'

        handle_vulnerability_ids(finding)

        vulnerability_ids = ['CVE']

        self.assertEqual(2, len(mock.mock_calls))
        self.assertEqual('CVE', mock.mock_calls[0].kwargs['vulnerability_id'])
        self.assertEqual('CVE', mock.mock_calls[0].kwargs['finding'].cve)
        self.assertEqual(vulnerability_ids, mock.mock_calls[0].kwargs['finding'].unsaved_vulnerability_ids)

    @patch('dojo.importers.utils.Vulnerability_Id', autospec=True)
    def test_handle_vulnerability_ids_references_and_no_cve(self, mock):
        finding = Finding()
        finding.unsaved_vulnerability_ids = ['REF-1', 'REF-2']

        handle_vulnerability_ids(finding)

        vulnerability_ids = ['REF-1', 'REF-2']

        self.assertEqual(4, len(mock.mock_calls))
        self.assertEqual('REF-1', mock.mock_calls[0].kwargs['vulnerability_id'])
        self.assertEqual('REF-1', mock.mock_calls[0].kwargs['finding'].cve)
        self.assertEqual(vulnerability_ids, mock.mock_calls[2].kwargs['finding'].unsaved_vulnerability_ids)
        self.assertEqual('REF-2', mock.mock_calls[2].kwargs['vulnerability_id'])
        self.assertEqual('REF-1', mock.mock_calls[2].kwargs['finding'].cve)
        self.assertEqual(vulnerability_ids, mock.mock_calls[2].kwargs['finding'].unsaved_vulnerability_ids)

    @patch('dojo.importers.utils.Vulnerability_Id', autospec=True)
    def test_no_handle_vulnerability_ids_references_and_no_cve(self, mock):
        finding = Finding()

        handle_vulnerability_ids(finding)

        mock.assert_not_called()
