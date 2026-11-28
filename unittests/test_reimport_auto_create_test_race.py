"""
Reimports that arrive together and have to create their test create one test.

/api/v2/reimport-scan/ with auto_create_context reimports into the test of the named engagement that
has the request's scan type and test_title, and creates that test when there is none. Two requests
that arrived together both found no test, and each created its own, so the engagement was left with
two tests of one title. The test is now looked for again, and created, under a lock on the engagement
row, and the request that finds the other one's test reimports into it once the import that created
it has finished.

These run requests on real, separate database connections with committed rows, which a TestCase
cannot do; see test_dedupe_delete_commit_race for the harness they share.
"""

import threading
from contextlib import contextmanager
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, override_settings
from parameterized import parameterized
from rest_framework.test import APIClient

from dojo.importers import import_lock
from dojo.importers.auto_create_context import AutoCreateContextManager
from dojo.importers.default_importer import DefaultImporter
from dojo.models import Development_Environment, Finding, Test, Test_Import, User
from unittests.dojo_test_case import get_unit_tests_scans_path
from unittests.test_dedupe_delete_commit_race import (
    WAIT_TIMEOUT_SECONDS,
    _ConcurrentThread,
    _DupeDeleteDuringWriteMixin,
    _wait_for,
)
from unittests.test_import_serialized_per_test import _import_turn_holders

TEST_TITLE = "Nightly scan"


# Regression: two reimport-scan calls with auto_create_context for a test that did not exist yet
# each created one, leaving duplicate tests for the same engagement, scan type and title.
@override_settings(SERIALIZE_TEST_IMPORTS_WAIT_SECONDS=WAIT_TIMEOUT_SECONDS)
class TestReimportsArrivingTogetherCreateOneTest(_DupeDeleteDuringWriteMixin, SimpleTestCase):

    """Two reimports by name into a test that does not exist yet end up in the same test."""

    # Deduplication is on (the mixin turns it on) but nothing is deleted: these tests are about
    # two requests, not about the delete.
    DELETE_DUPLICATES = False

    def _api_clients(self):
        # One client per request thread. The API resolves the environment by name, and these tests commit their
        # rows into a database that may have none yet; the mixin's cleanup removes every row a test committed.
        Development_Environment.objects.get_or_create(name="Development")
        superuser = User.objects.create(username=f"reimport_race_su_{self.suffix}", is_superuser=True, is_staff=True)
        clients = [APIClient(), APIClient()]
        for client in clients:
            client.force_authenticate(user=superuser)
        return clients

    def _report_of(self, sample):
        if sample is None:
            return self._report()
        parser, filename = sample
        return SimpleUploadedFile(filename, (get_unit_tests_scans_path(parser) / filename).read_bytes())

    def _post_reimport(self, client, scan_type, sample, test_title):
        return client.post("/api/v2/reimport-scan/", {
            "product_name": self.product.name,
            "engagement_name": self.engagement.name,
            "auto_create_context": True,
            "scan_type": scan_type,
            "file": self._report_of(sample),
            "deduplication_execution_mode": "sync",
            **({"test_title": test_title} if test_title else {}),
        }, format="multipart", secure=True)

    def _start_two_reimports(self, scan_type, sample=None, test_title=TEST_TITLE):
        requests = [
            _ConcurrentThread(lambda client=client: self._post_reimport(client, scan_type, sample, test_title))
            for client in self._api_clients()
        ]
        for request in requests:
            request.start()
        return requests

    @contextmanager
    def _both_requests_find_no_test(self):
        """Hold each request where it has found no test and is about to create one, until both are there."""
        real_get_or_create_engagement = AutoCreateContextManager.get_or_create_engagement
        both_found_no_test = threading.Barrier(2, timeout=WAIT_TIMEOUT_SECONDS)

        def get_engagement_then_wait_for_the_other(manager, **kwargs):
            engagement = real_get_or_create_engagement(manager, **kwargs)
            both_found_no_test.wait()
            return engagement

        with patch.object(AutoCreateContextManager, "get_or_create_engagement", get_engagement_then_wait_for_the_other):
            yield

    def _findings_of(self, test):
        return Finding.objects.filter(test=test).count()

    def assertBothReimportedIntoOneTest(self, requests, test, findings):
        for request in requests:
            self.assertEqual(request.result.status_code, 201, msg=request.result.content[:800])
        self.assertEqual(
            {request.result.json()["test"] for request in requests}, {test.id},
            msg="the two requests answered with different tests",
        )
        self.assertEqual(
            self._findings_of(test), findings,
            msg="the request that found the other one's test reimports into it, adding no findings of its own",
        )
        self.assertEqual(
            sorted(Test_Import.objects.filter(test=test).values_list("type", flat=True)),
            [Test_Import.IMPORT_TYPE, Test_Import.REIMPORT_TYPE],
            msg="one request imports into the test it created and the other reimports into it",
        )
        self.assertEqual(_import_turn_holders(test.id), [], msg="a request left the test locked")

    @parameterized.expand([
        # The parser names the test type from the report (get_tests), and this report names no tool.
        ("report_naming_no_tool", "Generic Findings Import", None, TEST_TITLE, "Generic Findings Import", 3),
        # The same parser, and the report names its tool: the new test takes its type from the report.
        (
            "report_naming_its_tool", "Generic Findings Import", ("generic", "generic_custom_test.json"), TEST_TITLE,
            "Tool 1 Scan (Generic Findings Import)", 1,
        ),
        # A parser that leaves the test type to the scan type.
        ("scan_type_as_test_type", "Bandit Scan", ("bandit", "one_vuln.json"), TEST_TITLE, "Bandit Scan", 1),
        # No title: the reimport targets the engagement's latest test of the scan type.
        ("without_a_test_title", "Bandit Scan", ("bandit", "one_vuln.json"), None, "Bandit Scan", 1),
    ])
    def test_two_reimports_arriving_together_create_one_test(
        self, case_name, scan_type, sample, test_title, test_type_name, findings,
    ):
        with self._both_requests_find_no_test(), patch.object(import_lock, "TEST_IMPORT_TURN_POLL_SECONDS", 0.05):
            requests = self._start_two_reimports(scan_type, sample, test_title)
            for request in requests:
                request.join_or_fail(self)

        tests = Test.objects.filter(engagement=self.engagement, scan_type=scan_type, title=test_title)
        self.assertEqual(
            tests.count(), 1,
            msg="each request created a test of its own for the same engagement, scan type and title",
        )
        test = tests.get()
        self.assertEqual(test.test_type.name, test_type_name)
        self.assertBothReimportedIntoOneTest(requests, test, findings)

    def test_the_reimport_waits_for_the_import_that_created_its_test(self):
        real_parse_findings = DefaultImporter.parse_findings
        let_the_import_go_on = threading.Event()

        def parse_findings_pausing_the_import(importer, *args, **kwargs):
            # The request that created the test has not started on its findings yet.
            let_the_import_go_on.wait(WAIT_TIMEOUT_SECONDS)
            return real_parse_findings(importer, *args, **kwargs)

        real_holders = import_lock._import_lock_holders
        reimport_found_the_test_taken = threading.Event()

        def holders_seen_by_a_waiting_import(*args, **kwargs):
            reimport_found_the_test_taken.set()
            return real_holders(*args, **kwargs)

        with (
            self._both_requests_find_no_test(),
            patch.object(DefaultImporter, "parse_findings", parse_findings_pausing_the_import),
            patch.object(import_lock, "_import_lock_holders", holders_seen_by_a_waiting_import),
            patch.object(import_lock, "TEST_IMPORT_TURN_POLL_SECONDS", 0.05),
        ):
            requests = self._start_two_reimports("Generic Findings Import")
            try:
                _wait_for(
                    lambda: reimport_found_the_test_taken.is_set() or not all(request.is_alive() for request in requests),
                    "the other request to find the new test being imported",
                )
                self.assertTrue(
                    all(request.is_alive() for request in requests),
                    msg="a request finished while the import that creates the test had not started on its findings",
                )
                test = Test.objects.get(engagement=self.engagement, title=TEST_TITLE)
                self.assertEqual(
                    self._findings_of(test), 0,
                    msg="the reimport wrote findings into the new test ahead of the import that created it",
                )
            finally:
                let_the_import_go_on.set()
                for request in requests:
                    request.join(WAIT_TIMEOUT_SECONDS)
            for request in requests:
                request.join_or_fail(self)

        self.assertBothReimportedIntoOneTest(requests, test, self.FINDINGS_IN_REPORT)
