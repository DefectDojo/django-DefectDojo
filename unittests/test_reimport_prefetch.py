"""
Regression tests for handling duplicate findings within the same reimport report.

When a scan report contains two findings that produce the same hash_code, the first
creates a new finding via process_finding_that_was_not_matched() and gets added to
the candidate dictionaries. When the second finding in the same batch matches against
this newly-created finding, accessing existing_finding.status_finding_non_special
raises AttributeError because the finding was never loaded through
build_candidate_scope_queryset (which sets up the Prefetch with to_attr).

Bugfix: https://github.com/DefectDojo/django-DefectDojo/pull/14569
Batch endpoint optimization (related): https://github.com/DefectDojo/django-DefectDojo/pull/14489
"""


from crum import impersonate
from django.conf import settings
from django.test import override_settings
from django.utils import timezone

from dojo.importers.default_reimporter import DefaultReImporter
from dojo.location.models import LocationFindingReference
from dojo.location.status import FindingLocationStatus
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
    Test_Type,
    User,
    UserContactInfo,
)

from .dojo_test_case import DojoTestCase, get_unit_tests_scans_path, skip_unless_v2

SCAN_TYPE = "StackHawk HawkScan"

# Reimport: two findings with different pluginIds (so the parser keeps both as separate
# findings) but identical hash_code fields (component_name + component_version).
# Each finding has one unique endpoint/location path (/app/login and /app/dashboard).
# This triggers the same-batch matching scenario where the second finding matches
# against the first one that was just created in the same reimport batch.
REIMPORT_SCAN = get_unit_tests_scans_path("stackhawk") / "stackhawk_two_vul_same_hashcode_fabricated.json"


def _hashcode_fields_without_vuln_id():
    """
    Return a copy of HASHCODE_FIELDS_PER_SCANNER with StackHawk configured to
    hash only on component_name + component_version (excluding vuln_id_from_tool).

    By default StackHawk hashes on [vuln_id_from_tool, component_name, component_version].
    Since vuln_id_from_tool maps to pluginId and the parser deduplicates by pluginId,
    it is normally impossible for two separate findings to share a hash_code.

    By removing vuln_id_from_tool from the hash fields, two findings with different
    pluginIds but the same application/env metadata will produce the same hash_code,
    allowing us to exercise the same-batch matching code path.
    """
    fields = dict(settings.HASHCODE_FIELDS_PER_SCANNER)
    fields[SCAN_TYPE] = ["component_name", "component_version"]
    return fields


class ReimportDuplicateFindingsTestBase(DojoTestCase):

    """Shared setup for duplicate-findings-in-same-report tests."""

    def setUp(self):
        super().setUp()
        testuser, _ = User.objects.get_or_create(username="admin")
        UserContactInfo.objects.get_or_create(user=testuser, defaults={"block_execution": True})

        self.system_settings(enable_deduplication=True)
        self.system_settings(enable_product_grade=False)

        product_type, _ = Product_Type.objects.get_or_create(name="test")
        product, _ = Product.objects.get_or_create(
            name="ReimportPrefetchTest",
            description="Test",
            prod_type=product_type,
        )
        engagement, _ = Engagement.objects.get_or_create(
            name="Test Engagement",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.lead, _ = User.objects.get_or_create(username="admin")
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        test_type, _ = Test_Type.objects.get_or_create(name=SCAN_TYPE)
        self.test = Test.objects.create(
            engagement=engagement,
            test_type=test_type,
            scan_type=SCAN_TYPE,
            target_start=timezone.now(),
            target_end=timezone.now(),
            environment=environment,
        )
        self.product = product

    def _reimport_with_overridden_hashcode(self):
        """Reimport the two-finding scan file with overridden hash settings."""
        hashcode_override = _hashcode_fields_without_vuln_id()
        with (
            impersonate(Dojo_User.objects.get(username="admin")),
            override_settings(HASHCODE_FIELDS_PER_SCANNER=hashcode_override),
            REIMPORT_SCAN.open(encoding="utf-8") as scan,
        ):
            reimporter = DefaultReImporter(
                test=self.test,
                user=self.lead,
                lead=self.lead,
                scan_date=None,
                minimum_severity="Info",
                active=True,
                verified=True,
                sync=True,
                scan_type=SCAN_TYPE,
            )
            return reimporter.process_scan(scan)


@skip_unless_v2
class TestReimportDuplicateFindingsEndpointHandling(ReimportDuplicateFindingsTestBase):

    """Regression test: reimport must handle endpoints correctly for duplicate findings in the same report."""

    def test_reimport_duplicate_findings_in_same_report_endpoints(self):
        """
        Reimporting a report with two findings that share the same hash_code must
        not raise AttributeError on status_finding_non_special, and must correctly
        create endpoints for both findings.

        The scan file has two findings with different pluginIds, each with one
        unique endpoint (/app/login and /app/dashboard). With the overridden hash
        settings, both produce the same hash_code. The first finding is created as
        new and added to candidates. The second finding matches against it (a
        batch-created finding), and its endpoint is added via finding_post_processing.
        """
        # This previously raised:
        # AttributeError: 'Finding' object has no attribute 'status_finding_non_special'
        _test, _, len_new, len_closed, _, _, _ = self._reimport_with_overridden_hashcode()

        # The first finding is new (empty test, no candidates). The second finding
        # matches the first (same hash_code) so it is not counted as new.
        self.assertEqual(len_new, 1, "Reimport should create one new finding (second matches first)")
        self.assertEqual(len_closed, 0, "No findings should be closed")

        # Only one finding should exist — the second was matched to the first
        findings = Finding.objects.filter(test=self.test)
        self.assertEqual(findings.count(), 1, "Only one finding should exist after reimport")

        finding = findings.first()

        # The first finding (new, pluginId=90001) creates endpoint /app/login.
        # The second finding (pluginId=90002) matches the first via hash_code.
        # finding_post_processing runs for BOTH iterations, adding each finding's
        # endpoints to the (single) matched finding. So the finding ends up with
        # 2 endpoints: /app/login (from the first) and /app/dashboard (from the second).
        endpoints = Endpoint.objects.filter(product=self.product)
        self.assertEqual(endpoints.count(), 2, "Two endpoints should be created (one per finding in report)")

        endpoint_statuses = Endpoint_Status.objects.filter(finding=finding)
        self.assertEqual(endpoint_statuses.count(), 2, "Finding should have two endpoint statuses")

        # Because the second finding is dynamic, update_endpoint_status() compares
        # the first finding's existing endpoint statuses against the second finding's
        # unsaved_endpoints. The second finding only has /app/dashboard, so /app/login
        # (which belongs to the first finding) is considered "no longer present" and
        # gets mitigated. This is arguably wrong for batch-created findings — both
        # endpoints came from the same report — but it is the current behavior.
        self.assertEqual(
            endpoint_statuses.filter(mitigated=False).count(),
            1,
            "One endpoint status should be active (/app/dashboard from the matched finding)",
        )
        self.assertEqual(
            endpoint_statuses.filter(mitigated=True).count(),
            1,
            "One endpoint status should be mitigated (/app/login — mitigated by update_endpoint_status "
            "because it is not in the second finding's endpoint list)",
        )


@override_settings(V3_FEATURE_LOCATIONS=True)
class TestReimportDuplicateFindingsLocationHandling(ReimportDuplicateFindingsTestBase):

    """Test that reimport handles locations correctly for duplicate findings in the same report."""

    def test_reimport_duplicate_findings_in_same_report_locations(self):
        """
        Reimporting a report with two findings that share the same hash_code must
        correctly create locations for both findings.

        The locations code does not use the to_attr prefetch that caused the
        AttributeError in the endpoint code path, so it does not crash. However,
        the same logical issue applies: update_location_status() compares the
        batch-created finding's locations against the second finding's unsaved
        locations, mitigating locations that are "no longer present".

        The scan file has two findings with different pluginIds, each with one
        unique location (https://localhost:9000/app/login and .../app/dashboard).
        With the overridden hash settings, both produce the same hash_code. The
        first finding is created as new and added to candidates. The second finding
        matches against it (a batch-created finding).
        """
        _test, _, len_new, len_closed, _, _, _ = self._reimport_with_overridden_hashcode()

        # The first finding is new (empty test, no candidates). The second finding
        # matches the first (same hash_code) so it is not counted as new.
        self.assertEqual(len_new, 1, "Reimport should create one new finding (second matches first)")
        self.assertEqual(len_closed, 0, "No findings should be closed")

        # Only one finding should exist — the second was matched to the first
        findings = Finding.objects.filter(test=self.test)
        self.assertEqual(findings.count(), 1, "Only one finding should exist after reimport")

        finding = findings.first()

        # The first finding (new, pluginId=90001) creates location for /app/login.
        # The second finding (pluginId=90002) matches the first via hash_code.
        # finding_post_processing runs for BOTH iterations, adding each finding's
        # locations to the (single) matched finding. So the finding ends up with
        # 2 location references pointing to 2 distinct Location objects.
        location_refs = LocationFindingReference.objects.filter(finding=finding)
        self.assertEqual(location_refs.count(), 2, "Finding should have two location references")

        # Same behavior as endpoints: update_location_status() compares the first
        # finding's existing location refs against the second finding's unsaved_locations.
        # The second finding only has /app/dashboard, so /app/login (which belongs to
        # the first finding) is considered "no longer present" and gets mitigated.
        # This is arguably wrong for batch-created findings — both locations came from
        # the same report — but it is the current behavior.
        self.assertEqual(
            location_refs.filter(status=FindingLocationStatus.Active).count(),
            1,
            "One location ref should be active (/app/dashboard from the matched finding)",
        )
        self.assertEqual(
            location_refs.filter(status=FindingLocationStatus.Mitigated).count(),
            1,
            "One location ref should be mitigated (/app/login — mitigated by update_location_status "
            "because it is not in the second finding's location list)",
        )
