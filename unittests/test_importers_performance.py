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

import json
import logging
import tempfile
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from crum import impersonate
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.db import connection
from django.test import override_settings, tag
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from dojo.auditlog import configure_audit_system, configure_pghistory_triggers
from dojo.decorators import dojo_async_task_counter
from dojo.importers.default_importer import DefaultImporter
from dojo.importers.default_reimporter import DefaultReImporter
from dojo.location.models import Location, LocationFindingReference
from dojo.models import (
    Development_Environment,
    Dojo_User,
    Endpoint,
    Endpoint_Status,
    Engagement,
    Finding,
    Finding_Group,
    FindingVulnerabilityReference,
    JIRA_Instance,
    JIRA_Issue,
    JIRA_Project,
    Product,
    Product_Type,
    Test,
    User,
    UserContactInfo,
)
from dojo.tools.stackhawk.parser import StackHawkParser

from .dojo_test_case import DojoTestCase, get_unit_tests_scans_path

logger = logging.getLogger(__name__)

STACK_HAWK_FILENAME = get_unit_tests_scans_path("stackhawk") / "stackhawk_many_vul_without_duplicated_findings.json"
STACK_HAWK_SUBSET_FILENAME = get_unit_tests_scans_path("stackhawk") / "stackhawk_many_vul_without_duplicated_findings_subset.json"
STACK_HAWK_EMPTY = get_unit_tests_scans_path("stackhawk") / "stackhawk_empty.json"
STACK_HAWK_SCAN_TYPE = "StackHawk HawkScan"


class TestDojoImporterPerformanceBase(DojoTestCase):

    """Base class for performance tests with shared setup and helper methods."""

    def setUp(self):
        super().setUp()

        testuser, _ = User.objects.get_or_create(username="admin")
        UserContactInfo.objects.update_or_create(user=testuser, defaults={"block_execution": False})

        self.system_settings(enable_product_grade=False)
        self.system_settings(enable_github=False)
        self.system_settings(enable_deduplication=True)

        # Warm up ContentType cache for relevant models. This is needed if we want to be able to run the test in isolation
        # As part of the test suite the ContentTYpe ids will already be cached and won't affect the query count.
        # But if we run the test in isolation, the ContentType ids will not be cached and will result in more queries.
        # By warming up the cache here, these queries are executed before we start counting queries
        for model in [Development_Environment, Dojo_User, Endpoint, Endpoint_Status, Engagement, Finding, Product, Product_Type, User, Test, FindingVulnerabilityReference]:
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
        expected_num_queries4,
        expected_num_async_tasks4,
        scan_file1,
        scan_file2,
        scan_file3,
        scan_file4,
        scan_type,
        product_name,
        engagement_name,
        *,
        close_old_findings4=False,
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
                                "service": "Secured Application",
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
                                "service": "Secured Application",
                            }
                            reimporter = DefaultReImporter(**reimport_options)
                            test, _, _len_new_findings, _len_closed_findings, _, _, _ = reimporter.process_scan(scan)

        # Fourth import (reimport again, empty report)
        # Each assertion context manager is wrapped in its own subTest so that if one fails, the others still run.
        # This allows us to see all count mismatches in a single test run, making it easier to fix
        # all incorrect expected values at once rather than fixing them one at a time.
        # Nested with statements are intentional - each assertion needs its own subTest wrapper.
        with (  # noqa: SIM117
            self.subTest("reimport3"), impersonate(Dojo_User.objects.get(username="admin")),
            scan_file4.open(encoding="utf-8") as scan,
        ):
            with self.subTest(step="reimport3", metric="queries"):
                with self.assertNumQueries(expected_num_queries4):
                    with self.subTest(step="reimport3", metric="async_tasks"):
                        with self._assertNumAsyncTask(expected_num_async_tasks4):
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
                                # StackHawk parser sets the service field causing close old findings to fail if we do not specify the service field
                                # This is a big problem that needs fixing. Parsers should not set the service field.
                                "service": "Secured Application",
                                "close_old_findings": close_old_findings4,
                            }
                            reimporter = DefaultReImporter(**reimport_options)
                            test, _, len_new_findings4, len_closed_findings4, _, _, _ = reimporter.process_scan(scan)
        logger.info("Step 4: new=%s closed=%s", len_new_findings4, len_closed_findings4)
        self.assertGreater(len_closed_findings4, 0, "Step 4 (empty reimport with close_old_findings=True) should close findings")


@tag("performance")
@override_settings(V3_FEATURE_LOCATIONS=False, SETTINGS_CACHE_L1_TTL=30, SETTINGS_CACHE_L2_TTL=-1)
class TestDojoImporterPerformanceSmall(TestDojoImporterPerformanceBase):

    """Performance tests using small sample files (StackHawk, ~6 findings)."""

    def setUp(self):
        super().setUp()

        original_get_findings = StackHawkParser.get_findings

        def _patched_get_findings(parser_self, json_output, test):
            findings = original_get_findings(parser_self, json_output, test)
            for f in findings:
                f.unsaved_tags = ["perf-tag-a", "perf-tag-b"]
                f.unsaved_vulnerability_ids = [f"CVE-2021-{f.vuln_id_from_tool}"]
            return findings

        patcher = patch.object(StackHawkParser, "get_findings", _patched_get_findings)
        patcher.start()
        self.addCleanup(patcher.stop)

        hashcode_override = override_settings(
            HASHCODE_FIELDS_PER_SCANNER={
                **settings.HASHCODE_FIELDS_PER_SCANNER,
                "StackHawk HawkScan": ["vulnerability_ids", "vuln_id_from_tool"],
            },
        )
        hashcode_override.enable()
        self.addCleanup(hashcode_override.disable)

    def _import_reimport_performance(self, expected_num_queries1, expected_num_async_tasks1, expected_num_queries2, expected_num_async_tasks2, expected_num_queries3, expected_num_async_tasks3, expected_num_queries4, expected_num_async_tasks4):
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
            expected_num_queries4,
            expected_num_async_tasks4,
            scan_file1=STACK_HAWK_SUBSET_FILENAME,
            scan_file2=STACK_HAWK_FILENAME,
            scan_file3=STACK_HAWK_SUBSET_FILENAME,
            scan_file4=STACK_HAWK_EMPTY,
            scan_type=STACK_HAWK_SCAN_TYPE,
            product_name="TestDojoDefaultImporter",
            engagement_name="Test Create Engagement",
            close_old_findings4=True,
        )

    @override_settings(ENABLE_AUDITLOG=True)
    def test_import_reimport_reimport_performance_pghistory_async(self):
        """
        This test checks the performance of the importers when using django-pghistory and celery tasks in sync mode
        Query counts will need to be determined by running the test initially.
        """
        configure_audit_system()
        configure_pghistory_triggers()

        self._import_reimport_performance(
            expected_num_queries1=157,
            expected_num_async_tasks1=3,
            expected_num_queries2=131,
            expected_num_async_tasks2=2,
            expected_num_queries3=30,
            expected_num_async_tasks3=2,
            expected_num_queries4=51,
            expected_num_async_tasks4=1,
        )

    @override_settings(ENABLE_AUDITLOG=True)
    def test_import_reimport_reimport_performance_pghistory_no_async(self):
        """
        This test checks the performance of the importers when using django-pghistory and celery tasks in sync mode.
        Query counts will need to be determined by running the test initially.
        """
        configure_audit_system()
        configure_pghistory_triggers()

        testuser = User.objects.get(username="admin")
        testuser.usercontactinfo.block_execution = True
        testuser.usercontactinfo.save()

        self._import_reimport_performance(
            expected_num_queries1=190,
            expected_num_async_tasks1=3,
            expected_num_queries2=151,
            expected_num_async_tasks2=2,
            expected_num_queries3=47,
            expected_num_async_tasks3=2,
            expected_num_queries4=61,
            expected_num_async_tasks4=1,
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
            expected_num_queries1=200,
            expected_num_async_tasks1=6,
            expected_num_queries2=161,
            expected_num_async_tasks2=5,
            expected_num_queries3=56,
            expected_num_async_tasks3=4,
            expected_num_queries4=70,
            expected_num_async_tasks4=4,
        )

    # Deduplication is enabled in the tests above, but to properly test it we must run the same import twice and capture the results.
    def _deduplication_performance(self, expected_num_queries1, expected_num_async_tasks1, expected_num_queries2, expected_num_async_tasks2, *, check_duplicates=True, dedup_mode=None):
        """
        Test method to measure deduplication performance by importing the same scan twice.
        The second import should result in all findings being marked as duplicates.
        This is different from reimport as we create a new test each time.
        Uses hash ["vulnerability_ids", "endpoints"] — stable because both imports use the same file.
        """
        _, engagement, lead, environment = self._create_test_objects(
            "TestDojoDeduplicationPerformance",
            "Test Deduplication Performance Engagement",
        )

        with override_settings(
            HASHCODE_FIELDS_PER_SCANNER={
                **settings.HASHCODE_FIELDS_PER_SCANNER,
                "StackHawk HawkScan": ["vulnerability_ids", "endpoints"],
            },
        ):
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
                                    **({"deduplication_execution_mode": dedup_mode} if dedup_mode else {}),
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
                                    **({"deduplication_execution_mode": dedup_mode} if dedup_mode else {}),
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
            expected_num_queries1=93,
            expected_num_async_tasks1=3,
            expected_num_queries2=74,
            expected_num_async_tasks2=3,
            check_duplicates=False,  # Async mode - deduplication happens later
        )

    @override_settings(ENABLE_AUDITLOG=True)
    def test_deduplication_performance_pghistory_no_async(self):
        """Test deduplication performance with django-pghistory and celery tasks in sync mode."""
        configure_audit_system()
        configure_pghistory_triggers()

        # Enable deduplication
        self.system_settings(enable_deduplication=True)

        testuser = User.objects.get(username="admin")
        testuser.usercontactinfo.block_execution = True
        testuser.usercontactinfo.save()

        self._deduplication_performance(
            expected_num_queries1=126,
            expected_num_async_tasks1=3,
            expected_num_queries2=108,
            expected_num_async_tasks2=3,
        )

    @override_settings(ENABLE_AUDITLOG=True)
    def test_deduplication_performance_pghistory_async_wait(self):
        """
        Deduplication performance in the 'async_wait' execution mode: post-processing is
        dispatched to a background worker, then the request joins on the result before
        responding. The dedup queries run in the worker (a separate connection), NOT in
        the web request, so the only web-side cost over the plain async path is +2: the
        post-dedup notification refresh SELECT, plus one result-backend write from the
        per-dispatch ignore_result=False that lets the request join via AsyncResult.get().

        We do not use CELERY_TASK_ALWAYS_EAGER here — that would run the dispatched task
        inline on the request's connection and wrongly count the worker's dedup queries.
        Instead the dedup batch is dispatched async (not executed in-process) and the join
        (AsyncResult.get) is mocked to return immediately, simulating a worker that has
        finished. deduplication_complete is therefore True (so the refresh runs), but the
        findings are not actually deduplicated in-test, so check_duplicates is False.
        """
        configure_audit_system()
        configure_pghistory_triggers()

        # Enable deduplication
        self.system_settings(enable_deduplication=True)

        # Simulate the background worker's post-processing having completed so the join
        # returns instantly without executing dedup on the request's DB connection.
        with patch("celery.result.AsyncResult.get", return_value=None):
            self._deduplication_performance(
                expected_num_queries1=94,
                expected_num_async_tasks1=3,
                expected_num_queries2=75,
                expected_num_async_tasks2=3,
                dedup_mode="async_wait",
                check_duplicates=False,
            )


@tag("performance")
@override_settings(V3_FEATURE_LOCATIONS=True, SETTINGS_CACHE_L1_TTL=30, SETTINGS_CACHE_L2_TTL=-1)
class TestDojoImporterPerformanceSmallLocations(TestDojoImporterPerformanceBase):

    r"""
    Performance tests using small sample files (StackHawk, ~6 findings) with v3 locations enabled.

    These mirror TestDojoImporterPerformanceSmall but run with V3_FEATURE_LOCATIONS=True.
    Query counts are specific to the locations code path and will differ from the v2 endpoint counts.

    To determine or update the expected counts, run:
        python3 scripts/update_performance_test_counts.py
    """

    def setUp(self):
        super().setUp()
        # Warm up ContentType cache for Location models so these queries don't
        # count against the measured sections.
        for model in [Location, LocationFindingReference]:
            ContentType.objects.get_for_model(model)

        original_get_findings = StackHawkParser.get_findings

        def _patched_get_findings(parser_self, json_output, test):
            findings = original_get_findings(parser_self, json_output, test)
            for f in findings:
                f.unsaved_tags = ["perf-tag-a", "perf-tag-b"]
                f.unsaved_vulnerability_ids = [f"CVE-2021-{f.vuln_id_from_tool}"]
            return findings

        patcher = patch.object(StackHawkParser, "get_findings", _patched_get_findings)
        patcher.start()
        self.addCleanup(patcher.stop)

        hashcode_override = override_settings(
            HASHCODE_FIELDS_PER_SCANNER={
                **settings.HASHCODE_FIELDS_PER_SCANNER,
                "StackHawk HawkScan": ["vulnerability_ids", "vuln_id_from_tool"],
            },
        )
        hashcode_override.enable()
        self.addCleanup(hashcode_override.disable)

    def _import_reimport_performance(self, expected_num_queries1, expected_num_async_tasks1, expected_num_queries2, expected_num_async_tasks2, expected_num_queries3, expected_num_async_tasks3, expected_num_queries4, expected_num_async_tasks4):
        r"""
        Log output can be quite large as when the assertNumQueries fails, all queries are printed.
        It could be useful to capture the output in `less`:
            ./run-unittest.sh --test-case unittests.test_importers_performance.TestDojoImporterPerformanceSmallLocations 2>&1 | less
        Then search for `expected` to find the lines where the expected number of queries is printed.
        Or you can use `grep` to filter the output:
            ./run-unittest.sh --test-case unittests.test_importers_performance.TestDojoImporterPerformanceSmallLocations 2>&1 | grep expected -B 10
        """
        return super()._import_reimport_performance(
            expected_num_queries1,
            expected_num_async_tasks1,
            expected_num_queries2,
            expected_num_async_tasks2,
            expected_num_queries3,
            expected_num_async_tasks3,
            expected_num_queries4,
            expected_num_async_tasks4,
            scan_file1=STACK_HAWK_SUBSET_FILENAME,
            scan_file2=STACK_HAWK_FILENAME,
            scan_file3=STACK_HAWK_SUBSET_FILENAME,
            scan_file4=STACK_HAWK_EMPTY,
            scan_type=STACK_HAWK_SCAN_TYPE,
            product_name="TestDojoDefaultImporterLocations",
            engagement_name="Test Create Engagement Locations",
            close_old_findings4=True,
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
            expected_num_queries1=164,
            expected_num_async_tasks1=3,
            expected_num_queries2=140,
            expected_num_async_tasks2=2,
            expected_num_queries3=37,
            expected_num_async_tasks3=2,
            expected_num_queries4=56,
            expected_num_async_tasks4=1,
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
            expected_num_queries1=201,
            expected_num_async_tasks1=3,
            expected_num_queries2=164,
            expected_num_async_tasks2=2,
            expected_num_queries3=58,
            expected_num_async_tasks3=2,
            expected_num_queries4=66,
            expected_num_async_tasks4=1,
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
            expected_num_queries1=214,
            expected_num_async_tasks1=6,
            expected_num_queries2=177,
            expected_num_async_tasks2=5,
            expected_num_queries3=67,
            expected_num_async_tasks3=4,
            expected_num_queries4=78,
            expected_num_async_tasks4=4,
        )

    def _deduplication_performance(self, expected_num_queries1, expected_num_async_tasks1, expected_num_queries2, expected_num_async_tasks2, *, check_duplicates=True):
        """
        Test method to measure deduplication performance by importing the same scan twice.
        Mirrors TestDojoImporterPerformanceSmall._deduplication_performance but uses
        Locations-specific product/engagement names for test isolation.
        Uses hash ["vulnerability_ids", "endpoints"] — stable because both imports use the same file.
        """
        _, engagement, lead, environment = self._create_test_objects(
            "TestDojoDeduplicationPerformanceLocations",
            "Test Deduplication Performance Engagement Locations",
        )

        with override_settings(
            HASHCODE_FIELDS_PER_SCANNER={
                **settings.HASHCODE_FIELDS_PER_SCANNER,
                "StackHawk HawkScan": ["vulnerability_ids", "endpoints"],
            },
        ):
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

        logger.debug(f"First import: {len_new_findings1} new findings, {len_closed_findings1} closed findings")
        logger.debug(f"Second import: {len_new_findings2} new findings, {len_closed_findings2} closed findings")

        self.assertEqual(len_new_findings1, 6, "First import should create 6 new findings")
        self.assertEqual(len_closed_findings1, 0, "First import should not close any findings")
        self.assertEqual(len_new_findings2, 6, "Second import should report 6 new findings initially (before deduplication)")
        self.assertEqual(len_closed_findings2, 0, "Second import should not close any findings")

        if check_duplicates:
            active_findings = Finding.objects.filter(
                test__engagement=engagement,
                active=True,
                duplicate=False,
            ).count()
            duplicate_findings = Finding.objects.filter(
                test__engagement=engagement,
                duplicate=True,
            ).count()
            self.assertEqual(active_findings, 6, f"Expected 6 active findings, got {active_findings}")
            self.assertEqual(duplicate_findings, 6, f"Expected 6 duplicate findings, got {duplicate_findings}")
            total_findings = Finding.objects.filter(test__engagement=engagement).count()
            self.assertEqual(total_findings, 12, f"Expected 12 total findings, got {total_findings}")
        else:
            total_findings = Finding.objects.filter(test__engagement=engagement).count()
            self.assertEqual(total_findings, 12, f"Expected 12 total findings, got {total_findings}")

    @override_settings(ENABLE_AUDITLOG=True)
    def test_deduplication_performance_pghistory_async(self):
        """Test deduplication performance with django-pghistory and async tasks enabled."""
        configure_audit_system()
        configure_pghistory_triggers()

        self.system_settings(enable_deduplication=True)

        self._deduplication_performance(
            expected_num_queries1=100,
            expected_num_async_tasks1=3,
            expected_num_queries2=77,
            expected_num_async_tasks2=3,
            check_duplicates=False,  # Async mode - deduplication happens later
        )

    @override_settings(ENABLE_AUDITLOG=True)
    def test_deduplication_performance_pghistory_no_async(self):
        """Test deduplication performance with django-pghistory and async tasks disabled."""
        configure_audit_system()
        configure_pghistory_triggers()

        self.system_settings(enable_deduplication=True)

        testuser = User.objects.get(username="admin")
        testuser.usercontactinfo.block_execution = True
        testuser.usercontactinfo.save()

        self._deduplication_performance(
            expected_num_queries1=137,
            expected_num_async_tasks1=3,
            expected_num_queries2=115,
            expected_num_async_tasks2=3,
        )


GENERIC_SCAN_TYPE = "Generic Findings Import"


@tag("performance")
@override_settings(V3_FEATURE_LOCATIONS=False, SETTINGS_CACHE_L1_TTL=30, SETTINGS_CACHE_L2_TTL=-1)
class TestDojoReimportGroupJiraPerformance(TestDojoImporterPerformanceBase):

    """
    A reimport with group_by and a JIRA instance that keeps findings in sync decides, per group, whether to push
    the group to JIRA. Regression: that decision read each group and its JIRA issue one query at a time, so the
    reimport's statement count grew with the number of groups. The same findings are reimported here into 2 and
    into 10 groups, and the reimport runs the same number of statements either way.
    """

    FINDINGS = 20  # per report: the second half of the import is reimported, plus as many new findings

    def setUp(self):
        super().setUp()
        self.system_settings(enable_finding_groups=True, enable_jira=True)

    def _report(self, directory, name, titles, first):
        path = Path(directory) / f"{name}.json"
        findings = [
            {
                # Title case, as saved findings carry it: the reimport names a new finding's group from the
                # parsed title, so a lowercase one would land in a second group instead of the imported one.
                "title": f"Group Jira Rule {index % titles}",
                "severity": "High",
                "description": f"finding {index}",
                "file_path": f"src/file_{index}.py",
                "line": index + 1,
            }
            for index in range(first, first + self.FINDINGS)
        ]
        path.write_text(json.dumps({"findings": findings}), encoding="utf-8")
        return path

    def _reimport(self, titles):
        product, engagement, lead, environment = self._create_test_objects(f"Group JIRA {titles}", f"Group JIRA {titles}")
        jira_instance = JIRA_Instance.objects.create(
            configuration_name=f"group jira {titles}", url="https://jira.example.com", username="user", password="token",  # noqa: S106
            default_issue_type="Bug", epic_name_id=1, open_status_key=1, close_status_key=2,
            info_mapping_severity="Info", low_mapping_severity="Low", medium_mapping_severity="Medium",
            high_mapping_severity="High", critical_mapping_severity="Critical", finding_jira_sync=True,
        )
        jira_project = JIRA_Project.objects.create(jira_instance=jira_instance, product=product, project_key="GJP")
        common = {
            "user": lead, "lead": lead, "scan_date": None, "minimum_severity": "Info", "active": True, "verified": True,
            "sync": True, "scan_type": GENERIC_SCAN_TYPE, "group_by": "finding_title",
            "create_finding_groups_for_all_findings": True,
        }
        pushed = []
        with (
            tempfile.TemporaryDirectory() as directory,
            impersonate(Dojo_User.objects.get(username="admin")),
            patch("dojo.jira.services.push", side_effect=lambda obj, *_args, **_kwargs: pushed.append(obj)),
        ):
            with self._report(directory, "import", titles, 0).open(encoding="utf-8") as scan:
                test, *_ = DefaultImporter(engagement=engagement, environment=environment, **common).process_scan(scan)
            groups = list(Finding_Group.objects.filter(test=test))
            JIRA_Issue.objects.bulk_create(
                [JIRA_Issue(jira_project=jira_project, jira_id=str(g.id), jira_key=f"GJP-{g.id}", finding_group=g) for g in groups],
            )
            del pushed[:]
            with (
                self._report(directory, "reimport", titles, self.FINDINGS // 2).open(encoding="utf-8") as scan,
                CaptureQueriesContext(connection) as queries,
            ):
                DefaultReImporter(test=test, close_old_findings=False, **common).process_scan(scan)
        return groups, len(queries), pushed

    def test_reimport_group_jira_pass_does_not_grow_with_groups(self):
        """Ten groups cost the reimport no more statements than two; every group with a JIRA issue is still pushed."""
        counts = {}
        for titles in (2, 10):
            groups, statements, pushed = self._reimport(titles)
            self.assertEqual(len(groups), titles, f"groups formed by the import of {titles} titles")
            # each group gets a new finding (first pass) and keeps unchanged ones (second pass): pushed once per pass
            self.assertEqual(
                sorted((type(obj).__name__, obj.id) for obj in pushed),
                sorted(("Finding_Group", group.id) for group in groups for _ in range(2)),
                f"JIRA pushes with {titles} groups",
            )
            counts[titles] = statements
        self.assertEqual(
            counts[2], counts[10],
            f"the reimport ran {counts[2]} statements with 2 groups and {counts[10]} with 10",
        )
