import logging

from django.contrib.contenttypes.models import ContentType

from dojo.models import (
    Development_Environment,
    Dojo_User,
    Endpoint,
    Endpoint_Status,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    User,
    UserContactInfo,
)

from .dojo_test_case import DojoAPITestCase, get_unit_tests_scans_path

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


STACK_HAWK_FILENAME = get_unit_tests_scans_path("stackhawk") / "stackhawk_many_vul_without_duplicated_findings.json"
STACK_HAWK_SUBSET_FILENAME = get_unit_tests_scans_path("stackhawk") / "stackhawk_many_vul_without_duplicated_findings_subset.json"
STACK_HAWK_SCAN_TYPE = "StackHawk HawkScan"


class TestDojoImportersDeduplication(DojoAPITestCase):

    def setUp(self):
        super().setUp()

        testuser = User.objects.create(username="admin")
        testuser.is_superuser = True
        testuser.is_staff = True
        testuser.save()
        UserContactInfo.objects.create(user=testuser, block_execution=False)

        # Authenticate API client as admin for import endpoints
        self.login_as_admin()

        self.system_settings(enable_webhooks_notifications=False)
        self.system_settings(enable_product_grade=False)
        self.system_settings(enable_github=False)

        # Warm up ContentType cache for relevant models. This is needed if we want to be able to run the test in isolation
        # As part of the test suite the ContentTYpe ids will already be cached and won't affect the query count.
        # But if we run the test in isolation, the ContentType ids will not be cached and will result in more queries.
        # By warming up the cache here, these queries are executed before we start counting queries
        for model in [Development_Environment, Dojo_User, Endpoint, Endpoint_Status, Engagement, Finding, Product, Product_Type, User, Test]:
            ContentType.objects.get_for_model(model)

    def test_one_import_no_duplicate_findings(self):
        response_json = self.import_scan_with_params(
            STACK_HAWK_FILENAME,
            scan_type=STACK_HAWK_SCAN_TYPE,
            minimum_severity="Info",
            active=True,
            verified=True,
            engagement=None,
            product_type_name="PT StackHawk",
            product_name="P StackHawk",
            engagement_name="E StackHawk",
            auto_create_context=True,
        )

        test_id = response_json["test"]
        dup_count = Finding.objects.filter(test_id=test_id, duplicate=True).count()
        self.assertEqual(0, dup_count)
