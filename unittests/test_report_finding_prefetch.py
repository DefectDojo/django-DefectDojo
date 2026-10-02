"""
Regression tests for the finding report's ``vulnerability_references`` prefetch handling.

The finding-list report path (``POST /api/v2/findings/generate_report/``) hands the report
generator the finding viewset's ``get_queryset()``. When that queryset already prefetches
``vulnerability_references`` (the finding viewset does this so the finding serializer can render
vulnerability ids without an N+1), ``report_generate`` re-applied the report's own
``vulnerability_id_prefetch()`` on top through ``prefetch_related_findings_for_report``. The same
relation was then registered twice with two different ``Prefetch`` querysets, so Django raised::

    ValueError: 'vulnerability_references' lookup was already seen with a different queryset.
    You may need to adjust the ordering of your lookups.

while the report serializer iterated the queryset -- turning report generation into a 500.

``prefetch_related_findings_for_report`` is the sole authority for the report's finding prefetch
set, so it now clears any prefetch the caller already applied before layering on its own.
"""
from crum import impersonate
from rest_framework.test import APIRequestFactory

from dojo.api_v2.views import report_generate
from dojo.finding.helper import save_vulnerability_ids
from dojo.models import Finding, User
from dojo.reports.queries import prefetch_related_findings_for_report
from dojo.vulnerability.queries import vulnerability_id_prefetch
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


@versioned_fixtures
class ReportFindingVulnerabilityPrefetchTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.user = User.objects.get(username="admin")
        # A finding with a vulnerability reference, so the prefetch resolves a real row.
        self.finding = Finding.objects.get(id=7)
        save_vulnerability_ids(self.finding, ["CVE-2024-9999"])

    def _pre_prefetched_findings(self):
        # Mirror the finding viewset's get_queryset(), which already prefetches
        # vulnerability_references before the report path adds its own prefetch set.
        return Finding.objects.filter(id=self.finding.id).prefetch_related(
            vulnerability_id_prefetch(),
        )

    def test_prefetch_related_findings_for_report_tolerates_existing_vuln_prefetch(self):
        findings = prefetch_related_findings_for_report(self._pre_prefetched_findings())
        # Evaluating the queryset resolves every prefetch; this is exactly where the
        # duplicate-lookup ValueError used to fire.
        resolved = list(findings)
        self.assertIn(self.finding.id, {f.id for f in resolved})

    def test_report_generate_with_pre_prefetched_findings_queryset(self):
        request = APIRequestFactory().get("/api/v2/findings/generate_report/")
        request.user = self.user
        # impersonate a superuser so the report filter's authorization pass returns the
        # queryset unchanged (preserving its prefetches) instead of scoping it to none()
        # for the crum-less test context -- otherwise the conflicting prefetch is dropped
        # and the bug is not exercised end to end.
        with impersonate(self.user):
            data = report_generate(request, self._pre_prefetched_findings(), {"report_type": "JSON"})
            # data["findings"] is a queryset; forcing evaluation triggers prefetch resolution,
            # the operation that produced the customer-facing 500.
            report_findings = list(data["findings"])
        self.assertIn(self.finding.id, {f.id for f in report_findings})
