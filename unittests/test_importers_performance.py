"""
Performance tests for importers.

These tests verify that import and reimport operations maintain acceptable query counts
and async task counts to prevent performance regressions.

Counts can be updated via the Python script at scripts/update_performance_test_counts.py.
However, counts must be verified to ensure no implicit performance regressions are introduced.
When counts change, review the differences carefully to determine if they represent:
- Legitimate optimizations (counts decreasing)
- Acceptable changes due to feature additions (counts increasing with justification)
- Unintended performance regressions (counts increasing without clear reason)

Always verify updated counts by:
1. Running the update script to see the differences
2. Reviewing the changes to understand why counts changed
3. Running the verification step to ensure all tests pass
4. Investigating any unexpected increases in query or task counts
"""

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

from .dojo_test_case import DojoTestCase, get_unit_tests_scans_path, skip_unless_v2

logger = logging.getLogger(__name__)

STACK_HAWK_FILENAME = get_unit_tests_scans_path("stackhawk") / "stackhawk_many_vul_without_duplicated_findings.json"
STACK_HAWK_SUBSET_FILENAME = get_unit_tests_scans_path("stackhawk") / "stackhawk_many_vul_without_duplicated_findings_subset.json"
STACK_HAWK_SCAN_TYPE = "StackHawk HawkScan"


class TestDojoImporterPerformanceBase(DojoTestCase):

    """Base class for performance tests with shared setup and helper methods."""

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

    def _create_test_objects(self, product_name, engagement_name):
        """Helper method to create test product, engagement, lead user, and environment."""
        product_type, _created = Product_Type.objects.get_or_create(name="test")
        product, _created = Product.objects.get_or_create(
            name=product_name,
            description="Test",
            prod_type=product_type,
        )
        engagement, _created = Engagement.objects.get_or_create(
            name=engagement_name,
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        lead, _ = User.objects.get_or_create(username="admin")
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        return product, engagement, lead, environment

    def _import_reimport_performance(
        self,
        expected_num_queries1,
        expected_num_async_tasks1,
        expected_num_queries2,
        expected_num_async_tasks2,
        expected_num_queries3,
        expected_num_async_tasks3,
        scan_file1,
        scan_file2,
        scan_file3,
        scan_type,
        product_name,
        engagement_name,
    ):
        """
        Test import/reimport/reimport performance with specified scan files and scan type.
        Log output can be quite large as when the assertNumQueries fails, all queries are printed.
        """
        _, engagement, lead, environment = self._create_test_objects(
            product_name,
            engagement_name,
        )

        # First import
        # Each assertion context manager is wrapped in its own subTest so that if one fails, the others still run.
        # This allows us to see all count mismatches in a single test run, making it easier to fix
        # all incorrect expected values at once rather than fixing them one at a time.
        # Nested with statements are intentional - each assertion needs its own subTest wrapper.
        with (  # noqa: SIM117
            self.subTest("import1"), impersonate(Dojo_User.objects.get(username="admin")),
            scan_file1.open(encoding="utf-8") as scan,
        ):
            with self.subTest(step="import1", metric="queries"):
                with self.assertNumQueries(expected_num_queries1):
                    with self.subTest(step="import1", metric="async_tasks"):
                        with self._assertNumAsyncTask(expected_num_async_tasks1):
                            import_options = {
                                "user": lead,
                                "lead": lead,
                                "scan_date": None,
                                "environment": environment,
                                "minimum_severity": "Info",
                                "active": True,
                                "verified": True,
                                "sync": True,
                                "scan_type": scan_type,
                                "engagement": engagement,
                                "tags": ["performance-test", "tag-in-param", "go-faster"],
                                "apply_tags_to_findings": True,
                            }
                            importer = DefaultImporter(**import_options)
                            test, _, _len_new_findings, _len_closed_findings, _, _, _ = importer.process_scan(scan)

        # Second import (reimport)
        # Each assertion context manager is wrapped in its own subTest so that if one fails, the others still run.
        # This allows us to see all count mismatches in a single test run, making it easier to fix
        # all incorrect expected values at once rather than fixing them one at a time.
        # Nested with statements are intentional - each assertion needs its own subTest wrapper.
        with (  # noqa: SIM117
            self.subTest("reimport1"), impersonate(Dojo_User.objects.get(username="admin")),
            scan_file2.open(encoding="utf-8") as scan,
        ):
            with self.subTest(step="reimport1", metric="queries"):
                with self.assertNumQueries(expected_num_queries2):
                    with self.subTest(step="reimport1", metric="async_tasks"):
                        with self._assertNumAsyncTask(expected_num_async_tasks2):
                            reimport_options = {
                                "test": test,
                                "user": lead,
                                "lead": lead,
                                "scan_date": None,
                                "minimum_severity": "Info",
                                "active": True,
                                "verified": True,
                                "sync": True,
                                "scan_type": scan_type,
                                "tags": ["performance-test-reimport", "reimport-tag-in-param", "reimport-go-faster"],
                                "apply_tags_to_findings": True,
                            }
                            reimporter = DefaultReImporter(**reimport_options)
                            test, _, _len_new_findings, _len_closed_findings, _, _, _ = reimporter.process_scan(scan)

        # Third import (reimport again)
        # Each assertion context manager is wrapped in its own subTest so that if one fails, the others still run.
        # This allows us to see all count mismatches in a single test run, making it easier to fix
        # all incorrect expected values at once rather than fixing them one at a time.
        # Nested with statements are intentional - each assertion needs its own subTest wrapper.
        with (  # noqa: SIM117
            self.subTest("reimport2"), impersonate(Dojo_User.objects.get(username="admin")),
            scan_file3.open(encoding="utf-8") as scan,
        ):
            with self.subTest(step="reimport2", metric="queries"):
                with self.assertNumQueries(expected_num_queries3):
                    with self.subTest(step="reimport2", metric="async_tasks"):
                        with self._assertNumAsyncTask(expected_num_async_tasks3):
                            reimport_options = {
                                "test": test,
                                "user": lead,
                                "lead": lead,
                                "scan_date": None,
                                "minimum_severity": "Info",
                                "active": True,
                                "verified": True,
                                "sync": True,
                                "scan_type": scan_type,
                            }
                            reimporter = DefaultReImporter(**reimport_options)
                            test, _, _len_new_findings, _len_closed_findings, _, _, _ = reimporter.process_scan(scan)


# TODO: Implement Locations
@skip_unless_v2
class TestDojoImporterPerformanceSmall(TestDojoImporterPerformanceBase):

    """Performance tests using small sample files (StackHawk, ~6 findings)."""

    def _import_reimport_performance(self, expected_num_queries1, expected_num_async_tasks1, expected_num_queries2, expected_num_async_tasks2, expected_num_queries3, expected_num_async_tasks3):
        """
        Log output can be quite large as when the assertNumQueries fails, all queries are printed.
        It could be usefule to capture the output in `less`:
            ./run-unittest.sh --test-case unittests.test_importers_performance.TestDojoImporterPerformanceSmall 2>&1 | less
        Then search for `expected` to find the lines where the expected number of queries is printed.
        Or you can use `grep` to filter the output:
            ./run-unittest.sh --test-case unittests.test_importers_performance.TestDojoImporterPerformanceSmall 2>&1 | grep expected -B 10
        """
        return super()._import_reimport_performance(
            expected_num_queries1,
            expected_num_async_tasks1,
            expected_num_queries2,
            expected_num_async_tasks2,
            expected_num_queries3,
            expected_num_async_tasks3,
            scan_file1=STACK_HAWK_SUBSET_FILENAME,
            scan_file2=STACK_HAWK_FILENAME,
            scan_file3=STACK_HAWK_SUBSET_FILENAME,
            scan_type=STACK_HAWK_SCAN_TYPE,
            product_name="TestDojoDefaultImporter",
            engagement_name="Test Create Engagement",
        )

    @override_settings(ENABLE_AUDITLOG=True)
    def test_import_reimport_reimport_performance_pghistory_async(self):
        """
        This test checks the performance of the importers when using django-pghistory with async enabled.
        Query counts will need to be determined by running the test initially.
        """
        configure_audit_system()
        configure_pghistory_triggers()

        self._import_reimport_performance(
            expected_num_queries1=295,
            expected_num_async_tasks1=6,
            expected_num_queries2=227,
            expected_num_async_tasks2=17,
            expected_num_queries3=109,
            expected_num_async_tasks3=16,
        )

    @override_settings(ENABLE_AUDITLOG=True)
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
            expected_num_queries1=302,
            expected_num_async_tasks1=6,
            expected_num_queries2=234,
            expected_num_async_tasks2=17,
            expected_num_queries3=116,
            expected_num_async_tasks3=16,
        )

    @override_settings(ENABLE_AUDITLOG=True)
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
            expected_num_queries1=309,
            expected_num_async_tasks1=8,
            expected_num_queries2=241,
            expected_num_async_tasks2=19,
            expected_num_queries3=120,
            expected_num_async_tasks3=18,
        )

    # Deduplication is enabled in the tests above, but to properly test it we must run the same import twice and capture the results.
    def _deduplication_performance(self, expected_num_queries1, expected_num_async_tasks1, expected_num_queries2, expected_num_async_tasks2, *, check_duplicates=True):
        """
        Test method to measure deduplication performance by importing the same scan twice.
        The second import should result in all findings being marked as duplicates.
        This is different from reimport as we create a new test each time.
        """
        _, engagement, lead, environment = self._create_test_objects(
            "TestDojoDeduplicationPerformance",
            "Test Deduplication Performance Engagement",
        )

        # First import - all findings should be new
        # Each assertion context manager is wrapped in its own subTest so that if one fails, the others still run.
        # This allows us to see all count mismatches in a single test run, making it easier to fix
        # all incorrect expected values at once rather than fixing them one at a time.
        # Nested with statements are intentional - each assertion needs its own subTest wrapper.
        with (  # noqa: SIM117
            self.subTest("first_import"), impersonate(Dojo_User.objects.get(username="admin")),
            STACK_HAWK_FILENAME.open(encoding="utf-8") as scan,
        ):
            with self.subTest(step="first_import", metric="queries"):
                with self.assertNumQueries(expected_num_queries1):
                    with self.subTest(step="first_import", metric="async_tasks"):
                        with self._assertNumAsyncTask(expected_num_async_tasks1):
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
        # Each assertion context manager is wrapped in its own subTest so that if one fails, the others still run.
        # This allows us to see all count mismatches in a single test run, making it easier to fix
        # all incorrect expected values at once rather than fixing them one at a time.
        # Nested with statements are intentional - each assertion needs its own subTest wrapper.
        with (  # noqa: SIM117
            self.subTest("second_import"), impersonate(Dojo_User.objects.get(username="admin")),
            STACK_HAWK_FILENAME.open(encoding="utf-8") as scan,
        ):
            with self.subTest(step="second_import", metric="queries"):
                with self.assertNumQueries(expected_num_queries2):
                    with self.subTest(step="second_import", metric="async_tasks"):
                        with self._assertNumAsyncTask(expected_num_async_tasks2):
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

    @override_settings(ENABLE_AUDITLOG=True)
    def test_deduplication_performance_pghistory_async(self):
        """Test deduplication performance with django-pghistory and async tasks enabled."""
        configure_audit_system()
        configure_pghistory_triggers()

        # Enable deduplication
        self.system_settings(enable_deduplication=True)

        self._deduplication_performance(
            expected_num_queries1=264,
            expected_num_async_tasks1=7,
            expected_num_queries2=175,
            expected_num_async_tasks2=7,
            check_duplicates=False,  # Async mode - deduplication happens later
        )

    @override_settings(ENABLE_AUDITLOG=True)
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
            expected_num_queries1=271,
            expected_num_async_tasks1=7,
            expected_num_queries2=236,
            expected_num_async_tasks2=7,
        )
