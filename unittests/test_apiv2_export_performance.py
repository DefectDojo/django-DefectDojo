import base64
from unittest.mock import patch

from django.core.files.base import ContentFile
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from dojo.endpoint.models import Endpoint_Status
from dojo.endpoint.utils import endpoint_get_or_create
from dojo.finding.helper import save_vulnerability_ids
from dojo.location.feature import locations_enabled
from dojo.models import (
    BurpRawRequestResponse,
    Dojo_User,
    DojoMeta,
    FileUpload,
    Finding,
    Finding_Group,
    Notes,
    Product,
    Risk_Acceptance,
    Test,
)
from dojo.url.models import URL
from unittests.dojo_test_case import DojoAPITestCase, versioned_fixtures
from unittests.test_apiv2_export import admin_client

# Keyed on locations_enabled(). Each batch of findings runs one query per prefetch in finding_prefetch(): notes,
# their history, vulnerability_references, finding_cwe_set, reviewers, found_by, risk_acceptance_set, tags,
# jira_issue, finding_group_set, finding_group_set__jira_issue, files, burprawrequestresponse_set and finding_meta (14).
QUERIES_PER_FINDING_BATCH = {
    # Locations mode adds locations, locations__location and locations__location__tags.
    True: 17,
    # Endpoints mode adds status_finding (with its endpoint joined) and endpoint__tags.
    False: 16,
}


@versioned_fixtures
class TestProductExportQueryCount(DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.client = admin_client()
        self.admin = Dojo_User.objects.get(username="admin")
        self.product = Product.objects.get(id=2)
        self.url = reverse("export-product", args=[2])
        b"".join(self.client.get(self.url).streaming_content)

    def add_findings(self, product: Product, count: int, prefix: str) -> None:
        test = Test.objects.filter(engagement__product=product).order_by("id").first()
        risk_acceptance = Risk_Acceptance.objects.create(name=prefix, owner=self.admin)
        test.engagement.risk_acceptance.add(risk_acceptance)
        for i in range(count):
            finding = Finding.objects.create(title=f"{prefix}-{i}", test=test, reporter=self.admin, severity="High")
            finding.tags = "perf_a, perf_b"
            finding.save()
            save_vulnerability_ids(finding, [f"CVE-2024-{i:04d}"])
            for n in range(2):
                if locations_enabled():
                    url = URL.get_or_create_from_object(URL.from_value(f"https://{prefix}-{i}-{n}.example"))
                    url.location.associate_with_finding(finding)
                else:
                    endpoint, _ = endpoint_get_or_create(host=f"{prefix}-{i}-{n}.example", product=product)
                    Endpoint_Status.objects.create(finding=finding, endpoint=endpoint)
            finding.notes.add(Notes.objects.create(entry=f"{prefix}-{i}", author=self.admin))
            file_upload = FileUpload.objects.create(title="poc.txt", file=ContentFile(b"hello", name="poc.txt"))
            self.addCleanup(file_upload.file.storage.delete, file_upload.file.name)
            finding.files.add(file_upload)
            Finding_Group.objects.create(name=f"{prefix}-{i}", test=test, creator=self.admin).findings.add(finding)
            DojoMeta.objects.create(finding=finding, name="k", value="v")
            BurpRawRequestResponse.objects.create(
                finding=finding,
                burpRequestBase64=base64.b64encode(b"GET / HTTP/1.1"),
                burpResponseBase64=base64.b64encode(b"HTTP/1.1 200 OK"),
            )
            risk_acceptance.accepted_findings.add(finding)

    def measure(self, url) -> int:
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(url)
            if response.streaming:
                b"".join(response.streaming_content)
        self.assertEqual(200, response.status_code)
        return len(ctx)

    def test_query_count_is_constant_within_a_batch(self):
        self.add_findings(self.product, 8, "a")
        q_a = self.measure(self.url)
        self.add_findings(self.product, 8, "b")
        q_b = self.measure(self.url)
        self.assertEqual(q_a, q_b, f"The export stream issues {q_a} queries with 8 added findings and {q_b} with 16.")

    def test_query_count_per_batch_is_pinned(self):
        with patch("dojo.export.api.views.EXPORT_CHUNK_SIZE", 4):
            self.add_findings(self.product, 4, "c")
            q_1 = self.measure(self.url)
            self.add_findings(self.product, 4, "d")
            q_2 = self.measure(self.url)
        self.assertEqual(QUERIES_PER_FINDING_BATCH[locations_enabled()], q_2 - q_1, f"{q_1} queries before the extra batch, {q_2} after.")

    def test_manifest_query_count_is_constant(self):
        url = reverse("export-manifest")
        before = self.measure(url)
        self.add_findings(self.product, 8, "e")
        self.create_product("perf", prod_type=self.product.prod_type)
        after = self.measure(url)
        self.assertEqual(before, after, f"The manifest issues {before} queries before the added data and {after} after.")
