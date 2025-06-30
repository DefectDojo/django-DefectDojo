import logging
from contextlib import contextmanager
from unittest.mock import patch

from crum import impersonate
from django.utils import timezone

from dojo.decorators import dojo_async_task_counter
from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import Development_Environment, Dojo_User, Engagement, Product, Product_Type, User

from .dojo_test_case import DojoTestCase, get_unit_tests_scans_path

logger = logging.getLogger(__name__)

STACK_HAWK_FILENAME = get_unit_tests_scans_path("stackhawk") / "stackhawk_many_vul_without_duplicated_findings.json"
STACK_HAWK_SUBSET_FILENAME = get_unit_tests_scans_path("stackhawk") / "stackhawk_many_vul_without_duplicated_findings_subset.json"
STACK_HAWK_SCAN_TYPE = "StackHawk HawkScan"


class TestDojoImporterPerformance(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        user = User.objects.get(username="admin")
        user.usercontactinfo.block_execution = True
        user.save()

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
        """Despite all efforts, these imports here run in async mode, so celery tasks are executed in the background"""
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
            expected_num_queries1=617,
            expected_num_async_tasks1=18,
            expected_num_queries2=496,
            expected_num_async_tasks2=25,
            expected_num_queries3=348,
            expected_num_async_tasks3=21,
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
            expected_num_queries1=708,
            expected_num_async_tasks1=29,
            expected_num_queries2=566,
            expected_num_async_tasks2=32,
            expected_num_queries3=400,
            expected_num_async_tasks3=26,
        )
