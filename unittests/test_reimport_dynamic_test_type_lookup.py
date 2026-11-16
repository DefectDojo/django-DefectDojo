# Regression: a reimport by test title picked another tool's test when two tools share a title, then failed "Test type mismatch"
import logging
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.importers.auto_create_context import AutoCreateContextManager
from dojo.models import Development_Environment, Dojo_User, Finding, Test, Test_Type, User

from .dojo_test_case import DojoAPITestCase, get_unit_tests_scans_path
from .test_utils import assertImportModelsCreated

logger = logging.getLogger(__name__)

SCAN_TYPE = "GitLab SAST Report"
# Two GitLab SAST reports from different scanners: the parser names each report's test type
# after its scanner, so both are "GitLab SAST Report" scans with different test types.
NJSSCAN_REPORT = get_unit_tests_scans_path("gitlab_sast") / "gl-sast-report-confidence_v15.json"  # 8 findings
NJSSCAN_TYPE = "njsscan Scan (GitLab SAST Report)"
FSB_REPORT = get_unit_tests_scans_path("gitlab_sast") / "gl-sast-report-cwe_v15.json"  # 3 findings
FSB_TYPE = "Find Security Bugs Scan (GitLab SAST Report)"

PRODUCT_NAME = "Product Reimport Tool Type"
ENGAGEMENT_NAME = "Engagement Reimport Tool Type"
TEST_TITLE = "pipeline sast"


class ReimportByTitleMatchesReportToolTest(DojoAPITestCase):

    """
    A reimport that names its test by engagement, title and scan type has to land in the test
    of the same tool when one scan type covers several tools (GitLab SAST, SARIF, Generic).
    """

    def setUp(self):
        user, _ = User.objects.get_or_create(username="admin", is_superuser=True)
        token, _ = Token.objects.get_or_create(user=user)
        self.client = APIClient(raise_request_exception=True)
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        Development_Environment.objects.get_or_create(name="Development")
        product_type = self.create_product_type("Reimport Tool Type Org")
        self.product = self.create_product(PRODUCT_NAME, prod_type=product_type)
        self.engagement = self.create_engagement(ENGAGEMENT_NAME, product=self.product)

    def reimport(self, report, **kwargs):
        params = {
            "scan_type": SCAN_TYPE,
            "product_name": PRODUCT_NAME,
            "engagement": None,
            "engagement_name": ENGAGEMENT_NAME,
            "test_title": TEST_TITLE,
            "auto_create_context": True,
        }
        params.update(kwargs)
        return self.reimport_scan_with_params(None, report, **params)

    def assert_test(self, test_id, test_type_name, findings):
        test = Test.objects.get(id=test_id)
        self.assertEqual(
            test.test_type.name, test_type_name,
            msg=f"test {test_id} persisted test_type={test.test_type.name}, expected {test_type_name}",
        )
        count = Finding.objects.filter(test=test).count()
        self.assertEqual(count, findings, msg=f"test {test_id} ({test.test_type.name}) persisted {count} findings, expected {findings}")

    def test_two_tools_sharing_a_title_land_in_separate_tests(self):
        with assertImportModelsCreated(self, tests=1, engagements=0, products=0, product_types=0, endpoints=0):
            njsscan_test_id = self.reimport(NJSSCAN_REPORT)["test"]
        with assertImportModelsCreated(self, tests=1, engagements=0, products=0, product_types=0, endpoints=0):
            fsb_test_id = self.reimport(FSB_REPORT)["test"]
        self.assertNotEqual(njsscan_test_id, fsb_test_id)
        self.assert_test(njsscan_test_id, NJSSCAN_TYPE, 8)
        self.assert_test(fsb_test_id, FSB_TYPE, 3)

        # Each later reimport goes back to its own tool's test, whichever one was created last.
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, product_types=0, endpoints=0):
            self.assertEqual(self.reimport(NJSSCAN_REPORT)["test"], njsscan_test_id)
            self.assertEqual(self.reimport(FSB_REPORT)["test"], fsb_test_id)
        self.assert_test(njsscan_test_id, NJSSCAN_TYPE, 8)
        self.assert_test(fsb_test_id, FSB_TYPE, 3)

    def test_one_tool_reimports_into_its_test(self):
        njsscan_test_id = self.reimport(NJSSCAN_REPORT)["test"]
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, product_types=0, endpoints=0):
            self.assertEqual(self.reimport(NJSSCAN_REPORT)["test"], njsscan_test_id)
        self.assert_test(njsscan_test_id, NJSSCAN_TYPE, 8)

    def test_test_typed_as_the_bare_scan_type_still_matches(self):
        # A test created outside the dynamic path (or from a report naming no tool) carries the
        # bare scan type, which names no tool, so any tool's report may reimport into it.
        test = Test.objects.create(
            title=TEST_TITLE, scan_type=SCAN_TYPE, engagement=self.engagement,
            test_type=Test_Type.objects.get_or_create(name=SCAN_TYPE)[0],
            target_start=timezone.now(), target_end=timezone.now(),
        )
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, product_types=0, endpoints=0):
            self.assertEqual(self.reimport(FSB_REPORT)["test"], test.id)
        self.assertEqual(Finding.objects.filter(test=test).count(), 3)

    def test_other_tools_test_is_not_reused_without_auto_create(self):
        njsscan_test_id = self.reimport(NJSSCAN_REPORT)["test"]
        with assertImportModelsCreated(self, tests=0, engagements=0, products=0, product_types=0, endpoints=0):
            response = self.reimport(FSB_REPORT, auto_create_context=None, expected_http_status_code=400)
        # Rejected because no test of this tool exists, not because another tool's test was picked.
        self.assertNotIn("Test type mismatch", str(response), msg=f"response: {response}")
        self.assertIn(f'Test "{TEST_TITLE}" with scan_type "{SCAN_TYPE}" does not exist', str(response), msg=f"response: {response}")
        self.assert_test(njsscan_test_id, NJSSCAN_TYPE, 8)


class ReimportByTitleReportReadTest(DojoAPITestCase):

    """
    The tool lookup reads the uploaded report, so it runs only for a request that may import, with
    a report that is a file under the size limit, and only once per request.
    """

    def setUp(self):
        admin, _ = User.objects.get_or_create(username="admin", is_superuser=True)
        token, _ = Token.objects.get_or_create(user=admin)
        self.client = APIClient(raise_request_exception=True)
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        self.admin_token = token.key
        Development_Environment.objects.get_or_create(name="Development")
        product_type = self.create_product_type("Reimport Report Read Org")
        self.product = self.create_product(PRODUCT_NAME, prod_type=product_type)
        self.engagement = self.create_engagement(ENGAGEMENT_NAME, product=self.product)
        self.njsscan_test_id = self.reimport_scan_with_params(
            None, NJSSCAN_REPORT, scan_type=SCAN_TYPE, product_name=PRODUCT_NAME, engagement=None,
            engagement_name=ENGAGEMENT_NAME, test_title=TEST_TITLE, auto_create_context=True,
        )["test"]

    def client_for(self, token_key):
        client = APIClient(raise_request_exception=False)
        client.credentials(HTTP_AUTHORIZATION="Token " + token_key)
        return client

    def post_reimport(self, client, file):
        return client.post("/api/v2/reimport-scan/", {
            "scan_type": SCAN_TYPE,
            "product_name": PRODUCT_NAME,
            "engagement_name": ENGAGEMENT_NAME,
            "test_title": TEST_TITLE,
            "auto_create_context": True,
            "file": file,
        }, format="multipart")

    def spy_report_reads(self):
        read = AutoCreateContextManager._read_report_test_type_names
        return patch.object(AutoCreateContextManager, "_read_report_test_type_names", side_effect=read)

    def assert_only_the_njsscan_test(self):
        tests = list(Test.objects.filter(engagement=self.engagement).values_list("id", flat=True))
        self.assertEqual([self.njsscan_test_id], tests)

    def test_file_sent_as_a_text_field_is_a_400(self):
        # A `curl -F file=name` mistake: the permission check gets text, and the serializer reports the field.
        with self.spy_report_reads() as spy:
            response = self.post_reimport(self.client_for(self.admin_token), "not-a-file")
        self.assertEqual(400, response.status_code, response.content[:500])
        self.assertIn("file", response.json(), response.content[:500])
        self.assertEqual(0, spy.call_count)
        self.assert_only_the_njsscan_test()

    def test_user_who_cannot_import_is_refused_before_the_report_is_read(self):
        nobody = Dojo_User.objects.create(username="reimport-report-read-nobody", is_superuser=False)
        client = self.client_for(Token.objects.create(user=nobody).key)
        for report in (NJSSCAN_REPORT, FSB_REPORT):
            with self.subTest(report=report.name), self.spy_report_reads() as spy, report.open(encoding="utf-8") as file:
                response = self.post_reimport(client, file)
                self.assertEqual(403, response.status_code, response.content[:500])
                self.assertEqual(0, spy.call_count, f"the report was read for a refused request: {spy.call_args_list}")
        self.assert_only_the_njsscan_test()

    @override_settings(SCAN_FILE_MAX_SIZE=0.001)  # MB, and both reports are a few KB
    def test_report_over_the_size_limit_is_refused_before_it_is_read(self):
        with self.spy_report_reads() as spy, FSB_REPORT.open(encoding="utf-8") as file:
            response = self.post_reimport(self.client_for(self.admin_token), file)
        self.assertEqual(400, response.status_code, response.content[:500])
        self.assertIn("too large", response.content.decode(), response.content[:500])
        self.assertEqual(0, spy.call_count)
        self.assert_only_the_njsscan_test()

    def test_second_resolution_in_a_request_runs_no_query_on_a_hit(self):
        # The permission check, then the serializer (v2) or auto_import_scan (v3), resolve the same
        # target on one manager: the second resolution reuses the first one's report read and test.
        # A miss is never remembered, so the other tool's report looks its test up again.
        manager = AutoCreateContextManager()
        context = {"scan_type": SCAN_TYPE, "engagement": self.engagement, "test_title": TEST_TITLE}
        cases = (
            (NJSSCAN_REPORT, self.njsscan_test_id, 0),
            (FSB_REPORT, None, 1),
        )
        for report, expected_test_id, second_queries in cases:
            scan = SimpleUploadedFile(report.name, report.read_bytes(), content_type="application/json")
            with self.subTest(report=report.name), self.spy_report_reads() as spy:
                first = manager.get_target_test_if_exists(**context, scan=scan)
                with self.assertNumQueries(second_queries):
                    second = manager.get_target_test_if_exists(**context, scan=scan)
                self.assertEqual(expected_test_id, getattr(first, "id", None))
                self.assertEqual(expected_test_id, getattr(second, "id", None))
                self.assertEqual(1, spy.call_count)
