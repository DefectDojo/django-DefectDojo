import logging
from contextlib import contextmanager
from unittest.mock import patch

from crum import impersonate
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone

from dojo.decorators import dojo_async_task_counter
from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
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
)

from .dojo_test_case import DojoTestCase, get_unit_tests_scans_path

logger = logging.getLogger(__name__)

STACK_HAWK_FILENAME = get_unit_tests_scans_path("stackhawk") / "stackhawk_many_vul_without_duplicated_findings.json"
STACK_HAWK_SUBSET_FILENAME = get_unit_tests_scans_path("stackhawk") / "stackhawk_many_vul_without_duplicated_findings_subset.json"
STACK_HAWK_SCAN_TYPE = "StackHawk HawkScan"

NPM_AUDIT_NO_VULN_FILENAME = get_unit_tests_scans_path("npm_audit") / "one_vuln.json"
NPM_AUDIT_SCAN_TYPE = "NPM Audit Scan"


class TestDojoImporterPerformance(DojoTestCase):

    def setUp(self):
        super().setUp()

        self.system_settings(enable_webhooks_notifications=False)
        self.system_settings(enable_product_grade=False)
        self.system_settings(enable_github=False)

        # Warm up ContentType cache for relevant models. This is needed if we want to be able to run the test in isolation
        # As part of the test suite the ContentTYpe ids will already be cached and won't affect the query count.
        # But if we run the test in isolation, the ContentType ids will not be cached and will result in more queries.
        # By warming up the cache here, these queries are executed before we start counting queries
        for model in [Development_Environment, Dojo_User, Endpoint, Endpoint_Status, Engagement, Finding, Product, Product_Type, User, Test]:
            ContentType.objects.get_for_model(model)

    @contextmanager
    def assertNumAsyncTask(self, num):
        dojo_async_task_counter.start()
        try:
            yield
        finally:
            dojo_async_task_counter.stop()
        actual = dojo_async_task_counter.get()
        if actual != num:
            tasks = dojo_async_task_counter.get_tasks()
            tasks_str = "\n".join(str(task) for task in tasks)
            msg = (
                f"Expected {num} celery tasks, but {actual} were created.\n"
                f"Tasks created:\n{tasks_str}"
            )
            raise self.failureException(msg)

    def import_reimport_performance(self, expected_num_queries1, expected_num_async_tasks1, expected_num_queries2, expected_num_async_tasks2, expected_num_queries3, expected_num_async_tasks3):
        """
        Log output can be quite large as when the assertNumQueries fails, all queries are printed.
        It could be usefule to capture the output in `less`:
            ./run-unittest.sh --test-case unittests.test_importers_performance.TestDojoImporterPerformance 2>&1 | less
        Then search for `expected` to find the lines where the expected number of queries is printed.
        Or you can use `grep` to filter the output:
            ./run-unittest.sh --test-case unittests.test_importers_performance.TestDojoImporterPerformance 2>&1 | grep expected
        """
        product_type, _created = Product_Type.objects.get_or_create(name="test")
        product, _created = Product.objects.get_or_create(
            name="TestDojoDefaultImporter",
            prod_type=product_type,
        )
        engagement, _created = Engagement.objects.get_or_create(
            name="Test Create Engagement",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        lead, _ = User.objects.get_or_create(username="admin")
        environment, _ = Development_Environment.objects.get_or_create(name="Development")

        # first import the subset which missed one finding and a couple of endpoints on some of the findings
        with (
            self.subTest("import1"), impersonate(Dojo_User.objects.get(username="admin")),
            self.assertNumQueries(expected_num_queries1),
            self.assertNumAsyncTask(expected_num_async_tasks1),
            STACK_HAWK_SUBSET_FILENAME.open(encoding="utf-8") as scan,
        ):
            import_options = {
                "user": lead,
                "lead": lead,
                "scan_date": None,
                "environment": environment,
                "minimum_severity": "Info",
                "active": True,
                "verified": True,
                "sync": True,
                "scan_type": STACK_HAWK_SCAN_TYPE,
                "engagement": engagement,
                "tags": ["performance-test", "tag-in-param", "go-faster"],
                "apply_tags_to_findings": True,
            }
            importer = DefaultImporter(**import_options)
            test, _, _len_new_findings, _len_closed_findings, _, _, _ = importer.process_scan(scan)

        # use reimport with the full report so it add a finding and some endpoints
        with (
            self.subTest("reimport1"), impersonate(Dojo_User.objects.get(username="admin")),
            self.assertNumQueries(expected_num_queries2),
            self.assertNumAsyncTask(expected_num_async_tasks2),
            STACK_HAWK_FILENAME.open(encoding="utf-8") as scan,
        ):
            reimport_options = {
                "test": test,
                "user": lead,
                "lead": lead,
                "scan_date": None,
                "minimum_severity": "Info",
                "active": True,
                "verified": True,
                "sync": True,
                "scan_type": STACK_HAWK_SCAN_TYPE,
                "tags": ["performance-test-reimport", "reimport-tag-in-param", "reimport-go-faster"],
                "apply_tags_to_findings": True,
            }
            reimporter = DefaultReImporter(**reimport_options)
            test, _, _len_new_findings, _len_closed_findings, _, _, _ = reimporter.process_scan(scan)

        # use reimport with the subset again to close a finding and mitigate some endpoints
        with (
            self.subTest("reimport2"), impersonate(Dojo_User.objects.get(username="admin")),
            self.assertNumQueries(expected_num_queries3),
            self.assertNumAsyncTask(expected_num_async_tasks3),
            STACK_HAWK_SUBSET_FILENAME.open(encoding="utf-8") as scan,
        ):
            reimport_options = {
                "test": test,
                "user": lead,
                "lead": lead,
                "scan_date": None,
                "minimum_severity": "Info",
                "active": True,
                "verified": True,
                "sync": True,
                "scan_type": STACK_HAWK_SCAN_TYPE,
            }
            reimporter = DefaultReImporter(**reimport_options)
            test, _, _len_new_findings, _len_closed_findings, _, _, _ = reimporter.process_scan(scan)

    def test_import_reimport_reimport_performance(self):
        self.import_reimport_performance(
            expected_num_queries1=729,
            expected_num_async_tasks1=10,
            expected_num_queries2=685,
            expected_num_async_tasks2=22,
            expected_num_queries3=358,
            expected_num_async_tasks3=20,
        )

    @patch("dojo.decorators.we_want_async", return_value=False)
    def test_import_reimport_reimport_performance_no_async(self, mock):
        """
        This test checks the performance of the importers when they are run in sync mode.
        The reason for this is that we also want to be aware of when a PR affects the number of queries
        or async tasks created by a background task.
        The impersonate context manager above does not work as expected for disabling async,
        so we patch the we_want_async decorator to always return False.
        """
        self.import_reimport_performance(
            expected_num_queries1=719,
            expected_num_async_tasks1=10,
            expected_num_queries2=685,
            expected_num_async_tasks2=22,
            expected_num_queries3=358,
            expected_num_async_tasks3=20,
        )

    @patch("dojo.decorators.we_want_async", return_value=False)
    def test_import_reimport_reimport_performance_no_async_with_product_grading(self, mock):
        """
        This test checks the performance of the importers when they are run in sync mode.
        The reason for this is that we also want to be aware of when a PR affects the number of queries
        or async tasks created by a background task.
        The impersonate context manager above does not work as expected for disabling async,
        so we patch the we_want_async decorator to always return False.
        """
        self.system_settings(enable_product_grade=True)
        # Refresh the cache with the new settings
        from dojo.middleware import DojoSytemSettingsMiddleware
        DojoSytemSettingsMiddleware.load()

        self.import_reimport_performance(
            expected_num_queries1=749,
            expected_num_async_tasks1=15,
            expected_num_queries2=710,
            expected_num_async_tasks2=28,
            expected_num_queries3=378,
            expected_num_async_tasks3=25,
        )
