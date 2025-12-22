import logging
from contextlib import contextmanager

from crum import impersonate
from django.contrib.contenttypes.models import ContentType
from django.test import override_settings
from django.utils import timezone

from dojo.auditlog import configure_audit_system, configure_pghistory_triggers
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
    UserContactInfo,
)

from .dojo_test_case import DojoTestCase, get_unit_tests_scans_path

logger = logging.getLogger(__name__)

STACK_HAWK_FILENAME = get_unit_tests_scans_path("stackhawk") / "stackhawk_many_vul_without_duplicated_findings.json"
STACK_HAWK_SUBSET_FILENAME = get_unit_tests_scans_path("stackhawk") / "stackhawk_many_vul_without_duplicated_findings_subset.json"
STACK_HAWK_SCAN_TYPE = "StackHawk HawkScan"


class TestDojoImporterPerformance(DojoTestCase):

    def setUp(self):
        super().setUp()

        testuser = User.objects.create(username="admin")
        UserContactInfo.objects.create(user=testuser, block_execution=False)

        self.system_settings(enable_product_grade=False)
        self.system_settings(enable_github=False)
        self.system_settings(enable_deduplication=True)

        # Warm up ContentType cache for relevant models. This is needed if we want to be able to run the test in isolation
        # As part of the test suite the ContentTYpe ids will already be cached and won't affect the query count.
        # But if we run the test in isolation, the ContentType ids will not be cached and will result in more queries.
        # By warming up the cache here, these queries are executed before we start counting queries
        for model in [Development_Environment, Dojo_User, Endpoint, Endpoint_Status, Engagement, Finding, Product, Product_Type, User, Test]:
            ContentType.objects.get_for_model(model)

    @contextmanager
    def _assertNumAsyncTask(self, num):
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

        tasks = dojo_async_task_counter.get_tasks()
        tasks_str = "\n".join(str(task) for task in tasks)
        msg = (
            f"Correct number of {num} celery tasks were created.\n"
            f"Tasks created:\n{tasks_str}"
        )
        logger.debug(msg)

    def _import_reimport_performance(self, expected_num_queries1, expected_num_async_tasks1, expected_num_queries2, expected_num_async_tasks2, expected_num_queries3, expected_num_async_tasks3):
        """
        Log output can be quite large as when the assertNumQueries fails, all queries are printed.
        It could be usefule to capture the output in `less`:
            ./run-unittest.sh --test-case unittests.test_importers_performance.TestDojoImporterPerformance 2>&1 | less
        Then search for `expected` to find the lines where the expected number of queries is printed.
        Or you can use `grep` to filter the output:
            ./run-unittest.sh --test-case unittests.test_importers_performance.TestDojoImporterPerformance 2>&1 | grep expected -B 10
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
            self._assertNumAsyncTask(expected_num_async_tasks1),
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
            self._assertNumAsyncTask(expected_num_async_tasks2),
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
            self._assertNumAsyncTask(expected_num_async_tasks3),
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

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="django-auditlog")
    def test_import_reimport_reimport_performance_async(self):
        # Ensure django-auditlog is properly configured for this test
        configure_audit_system()
        configure_pghistory_triggers()

        self._import_reimport_performance(
            expected_num_queries1=340,
            expected_num_async_tasks1=7,
            expected_num_queries2=288,
            expected_num_async_tasks2=18,
            expected_num_queries3=175,
            expected_num_async_tasks3=17,
        )

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="django-pghistory")
    def test_import_reimport_reimport_performance_pghistory_async(self):
        """
        This test checks the performance of the importers when using django-pghistory with async enabled.
        Query counts will need to be determined by running the test initially.
        """
        configure_audit_system()
        configure_pghistory_triggers()

        self._import_reimport_performance(
            expected_num_queries1=306,
            expected_num_async_tasks1=7,
            expected_num_queries2=281,
            expected_num_async_tasks2=18,
            expected_num_queries3=170,
            expected_num_async_tasks3=17,
        )

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="django-auditlog")
    def test_import_reimport_reimport_performance_no_async(self):
        """
        This test checks the performance of the importers when they are run in sync mode.
        The reason for this is that we also want to be aware of when a PR affects the number of queries
        or async tasks created by a background task.
        The impersonate context manager above does not work as expected for disabling async,
        so we patch the we_want_async decorator to always return False.
        """
        configure_audit_system()
        configure_pghistory_triggers()

        testuser = User.objects.get(username="admin")
        testuser.usercontactinfo.block_execution = True
        testuser.usercontactinfo.save()
        self._import_reimport_performance(
            expected_num_queries1=346,
            expected_num_async_tasks1=6,
            expected_num_queries2=294,
            expected_num_async_tasks2=17,
            expected_num_queries3=181,
            expected_num_async_tasks3=16,
        )

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="django-pghistory")
    def test_import_reimport_reimport_performance_pghistory_no_async(self):
        """
        This test checks the performance of the importers when using django-pghistory with async disabled.
        Query counts will need to be determined by running the test initially.
        """
        configure_audit_system()
        configure_pghistory_triggers()

        testuser = User.objects.get(username="admin")
        testuser.usercontactinfo.block_execution = True
        testuser.usercontactinfo.save()

        self._import_reimport_performance(
            expected_num_queries1=312,
            expected_num_async_tasks1=6,
            expected_num_queries2=287,
            expected_num_async_tasks2=17,
            expected_num_queries3=176,
            expected_num_async_tasks3=16,
        )

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="django-auditlog")
    def test_import_reimport_reimport_performance_no_async_with_product_grading(self):
        """
        This test checks the performance of the importers when they are run in sync mode.
        The reason for this is that we also want to be aware of when a PR affects the number of queries
        or async tasks created by a background task.
        The impersonate context manager above does not work as expected for disabling async,
        so we patch the we_want_async decorator to always return False.
        """
        configure_audit_system()
        configure_pghistory_triggers()

        testuser = User.objects.get(username="admin")
        testuser.usercontactinfo.block_execution = True
        testuser.usercontactinfo.save()
        self.system_settings(enable_product_grade=True)

        self._import_reimport_performance(
            expected_num_queries1=348,
            expected_num_async_tasks1=8,
            expected_num_queries2=296,
            expected_num_async_tasks2=19,
            expected_num_queries3=183,
            expected_num_async_tasks3=18,
        )

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="django-pghistory")
    def test_import_reimport_reimport_performance_pghistory_no_async_with_product_grading(self):
        """
        This test checks the performance of the importers when using django-pghistory with async disabled and product grading enabled.
        Query counts will need to be determined by running the test initially.
        """
        configure_audit_system()
        configure_pghistory_triggers()

        testuser = User.objects.get(username="admin")
        testuser.usercontactinfo.block_execution = True
        testuser.usercontactinfo.save()
        self.system_settings(enable_product_grade=True)

        self._import_reimport_performance(
            expected_num_queries1=314,
            expected_num_async_tasks1=8,
            expected_num_queries2=289,
            expected_num_async_tasks2=19,
            expected_num_queries3=178,
            expected_num_async_tasks3=18,
        )

    # Deduplication is enabled in the tests above, but to properly test it we must run the same import twice and capture the results.
    def _deduplication_performance(self, expected_num_queries1, expected_num_async_tasks1, expected_num_queries2, expected_num_async_tasks2, *, check_duplicates=True):
        """
        Test method to measure deduplication performance by importing the same scan twice.
        The second import should result in all findings being marked as duplicates.
        This is different from reimport as we create a new test each time.
        """
        product_type, _created = Product_Type.objects.get_or_create(name="test")
        product, _created = Product.objects.get_or_create(
            name="TestDojoDeduplicationPerformance",
            prod_type=product_type,
        )
        engagement, _created = Engagement.objects.get_or_create(
            name="Test Deduplication Performance Engagement",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        lead, _ = User.objects.get_or_create(username="admin")
        environment, _ = Development_Environment.objects.get_or_create(name="Development")

        # First import - all findings should be new
        with (
            self.subTest("first_import"), impersonate(Dojo_User.objects.get(username="admin")),
            self.assertNumQueries(expected_num_queries1),
            self._assertNumAsyncTask(expected_num_async_tasks1),
            STACK_HAWK_FILENAME.open(encoding="utf-8") as scan,
        ):
            import_options = {
                "user": lead,
                "lead": lead,
                "scan_date": None,
                "environment": environment,
                "minimum_severity": "Info",
                "active": True,
                "verified": True,
                "scan_type": STACK_HAWK_SCAN_TYPE,
                "engagement": engagement,
            }
            importer = DefaultImporter(**import_options)
            _, _, len_new_findings1, len_closed_findings1, _, _, _ = importer.process_scan(scan)

        # Second import - all findings should be duplicates
        with (
            self.subTest("second_import"), impersonate(Dojo_User.objects.get(username="admin")),
            self.assertNumQueries(expected_num_queries2),
            self._assertNumAsyncTask(expected_num_async_tasks2),
            STACK_HAWK_FILENAME.open(encoding="utf-8") as scan,
        ):
            import_options = {
                "user": lead,
                "lead": lead,
                "scan_date": None,
                "environment": environment,
                "minimum_severity": "Info",
                "active": True,
                "verified": True,
                "scan_type": STACK_HAWK_SCAN_TYPE,
                "engagement": engagement,
            }
            importer = DefaultImporter(**import_options)
            _, _, len_new_findings2, len_closed_findings2, _, _, _ = importer.process_scan(scan)

        # Log the results for analysis
        logger.debug(f"First import: {len_new_findings1} new findings, {len_closed_findings1} closed findings")
        logger.debug(f"Second import: {len_new_findings2} new findings, {len_closed_findings2} closed findings")

        # Assert that process_scan results show no deduplication yet (deduplication happens asynchronously)
        # The second import should report 6 new findings because deduplication is not visible in the stats from the importer
        self.assertEqual(len_new_findings1, 6, "First import should create 6 new findings")
        self.assertEqual(len_closed_findings1, 0, "First import should not close any findings")
        self.assertEqual(len_new_findings2, 6, "Second import should report 6 new findings initially (before deduplication)")
        self.assertEqual(len_closed_findings2, 0, "Second import should not close any findings")

        # Verify that second import resulted in duplicates by checking the database
        # Only check duplicates in sync mode since deduplication happens asynchronously
        if check_duplicates:
            # Count active findings (non-duplicates) in the engagement
            active_findings = Finding.objects.filter(
                test__engagement=engagement,
                active=True,
                duplicate=False,
            ).count()

            # Count duplicate findings in the engagement
            duplicate_findings = Finding.objects.filter(
                test__engagement=engagement,
                duplicate=True,
            ).count()

            # We should have 6 active findings (from first import) and 6 duplicate findings (from second import)
            self.assertEqual(active_findings, 6, f"Expected 6 active findings, got {active_findings}")
            self.assertEqual(duplicate_findings, 6, f"Expected 6 duplicate findings, got {duplicate_findings}")

            # Total findings should be 12 (6 active + 6 duplicates)
            total_findings = Finding.objects.filter(test__engagement=engagement).count()
            self.assertEqual(total_findings, 12, f"Expected 12 total findings, got {total_findings}")
        else:
            # In async mode, just verify we have 12 total findings (deduplication happens in celery tasks)
            total_findings = Finding.objects.filter(test__engagement=engagement).count()
            self.assertEqual(total_findings, 12, f"Expected 12 total findings, got {total_findings}")

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="django-auditlog")
    def test_deduplication_performance_async(self):
        """
        Test deduplication performance with async tasks enabled.
        This test imports the same scan twice to measure deduplication query and task overhead.
        """
        configure_audit_system()
        configure_pghistory_triggers()

        # Enable deduplication
        self.system_settings(enable_deduplication=True)

        self._deduplication_performance(
            expected_num_queries1=311,
            expected_num_async_tasks1=8,
            expected_num_queries2=204,
            expected_num_async_tasks2=8,
            check_duplicates=False,  # Async mode - deduplication happens later
        )

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="django-pghistory")
    def test_deduplication_performance_pghistory_async(self):
        """Test deduplication performance with django-pghistory and async tasks enabled."""
        configure_audit_system()
        configure_pghistory_triggers()

        # Enable deduplication
        self.system_settings(enable_deduplication=True)

        self._deduplication_performance(
            expected_num_queries1=275,
            expected_num_async_tasks1=8,
            expected_num_queries2=185,
            expected_num_async_tasks2=8,
            check_duplicates=False,  # Async mode - deduplication happens later
        )

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="django-auditlog")
    def test_deduplication_performance_no_async(self):
        """Test deduplication performance with async tasks disabled."""
        configure_audit_system()
        configure_pghistory_triggers()

        # Enable deduplication
        self.system_settings(enable_deduplication=True)

        testuser = User.objects.get(username="admin")
        testuser.usercontactinfo.block_execution = True
        testuser.usercontactinfo.save()

        self._deduplication_performance(
            expected_num_queries1=317,
            expected_num_async_tasks1=7,
            expected_num_queries2=282,
            expected_num_async_tasks2=7,
        )

    @override_settings(ENABLE_AUDITLOG=True, AUDITLOG_TYPE="django-pghistory")
    def test_deduplication_performance_pghistory_no_async(self):
        """Test deduplication performance with django-pghistory and async tasks disabled."""
        configure_audit_system()
        configure_pghistory_triggers()

        # Enable deduplication
        self.system_settings(enable_deduplication=True)

        testuser = User.objects.get(username="admin")
        testuser.usercontactinfo.block_execution = True
        testuser.usercontactinfo.save()

        self._deduplication_performance(
            expected_num_queries1=281,
            expected_num_async_tasks1=7,
            expected_num_queries2=245,
            expected_num_async_tasks2=7,
        )
