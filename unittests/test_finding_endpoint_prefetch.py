"""Keep endpoint popovers from querying once per endpoint on findings lists."""

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.timezone import now

from dojo.finding.queries import prefetch_for_findings
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
)
from unittests.dojo_test_case import skip_unless_v2


@skip_unless_v2
class TestFindingEndpointPrefetch(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User.objects.create(
            username="endpoint-prefetch",
            is_staff=True,
            is_superuser=True,
        )
        product_type = Product_Type.objects.create(name="endpoint-prefetch")
        product = Product.objects.create(name="endpoint-prefetch", prod_type=product_type)
        engagement = Engagement.objects.create(
            product=product, target_start=now(), target_end=now(),
        )
        test_type = Test_Type.objects.create(name="endpoint-prefetch")
        environment = Development_Environment.objects.get_or_create(name="Development")[0]
        scan = Test.objects.create(
            engagement=engagement, test_type=test_type, environment=environment,
            target_start=now(), target_end=now(),
        )
        cls.finding_ids = []
        cls.expected_statuses = {}
        for finding_index in range(12):
            finding = Finding.objects.create(
                test=scan, reporter=cls.user, severity="High",
                title=f"Endpoint prefetch {finding_index}",
            )
            cls.finding_ids.append(finding.pk)
            cls.expected_statuses[finding.pk] = []
            for endpoint_index in range(3):
                host = f"endpoint-{finding_index}-{endpoint_index}.example"
                endpoint = Endpoint.objects.create(
                    product=product, protocol="https", host=host, path="login",
                )
                mitigated = endpoint_index == 1
                risk_accepted = endpoint_index == 2
                Endpoint_Status.objects.create(
                    finding=finding, endpoint=endpoint,
                    mitigated=mitigated, risk_accepted=risk_accepted,
                )
                cls.expected_statuses[finding.pk].append(
                    (f"https://{host}/login", mitigated, risk_accepted),
                )
        cls.empty_finding = Finding.objects.create(
            test=scan, reporter=cls.user, severity="High", title="No endpoints",
        )

    def test_reading_endpoint_statuses_needs_no_extra_queries(self):
        for prefetch_type in ("all", "open"):
            for count in (1, 12):
                with self.subTest(prefetch_type=prefetch_type, findings=count):
                    findings = list(prefetch_for_findings(
                        Finding.objects.filter(pk__in=self.finding_ids[:count]),
                        prefetch_type=prefetch_type,
                    ))
                    self.assertEqual(len(findings), count)
                    with self.assertNumQueries(0):
                        actual = {
                            finding.pk: [
                                (str(status.endpoint), status.mitigated, status.risk_accepted)
                                for status in finding.status_finding.all()
                            ]
                            for finding in findings
                        }
                    for finding in findings:
                        self.assertCountEqual(actual[finding.pk], self.expected_statuses[finding.pk])
                        self.assertEqual(finding.active_endpoint_count, 1)
                        self.assertEqual(finding.mitigated_endpoint_count, 2)

    def test_findings_without_endpoints(self):
        finding = list(prefetch_for_findings(
            Finding.objects.filter(pk=self.empty_finding.pk),
        ))[0]
        with self.assertNumQueries(0):
            self.assertEqual(list(finding.status_finding.all()), [])
            self.assertFalse(finding.endpoints.exists())
        self.assertEqual(finding.active_endpoint_count, 0)
        self.assertEqual(finding.mitigated_endpoint_count, 0)

    def test_findings_page_keeps_popovers_without_per_endpoint_queries(self):
        self.client.force_login(self.user)
        for view_name in ("all_findings", "open_findings"):
            with self.subTest(view=view_name):
                with CaptureQueriesContext(connection) as queries:
                    response = self.client.get(reverse(view_name), {"page_size": 25})
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, self.empty_finding.title)
                for statuses in self.expected_statuses.values():
                    for endpoint, mitigated, _risk_accepted in statuses:
                        marker = "&#10003;" if mitigated else "&#10005;"
                        self.assertContains(response, f"{marker} {endpoint}")
                endpoint_lookups = [
                    query["sql"] for query in queries
                    if 'FROM "dojo_endpoint"' in query["sql"] and "LIMIT 21" in query["sql"]
                ]
                self.assertEqual(endpoint_lookups, [])
