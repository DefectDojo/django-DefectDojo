import base64
import json
import uuid
from datetime import datetime

from django.core.files.base import ContentFile
from django.test import RequestFactory
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

import dojo
from dojo.export.api.serializers import (
    MAX_FILE_BYTES_DEFAULT,
    ExportFindingSerializer,
    ExportProductSerializer,
    ExportRiskAcceptanceSerializer,
    ExportUserSerializer,
    export_endpoint_entries,
    export_file,
    export_proof,
)
from dojo.finding.api.serializer import FindingSerializer
from dojo.location.feature import locations_enabled
from dojo.location.status import FindingLocationStatus
from dojo.models import (
    BurpRawRequestResponse,
    Dojo_User,
    DojoMeta,
    Engagement,
    FileUpload,
    Finding,
    Finding_Group,
    Notes,
    Product,
    Risk_Acceptance,
    System_Settings,
    Test,
    UserContactInfo,
)
from dojo.system_settings.ui.forms import SystemSettingsForm
from unittests.dojo_test_case import DojoAPITestCase, versioned_fixtures


def user_client(username):
    token = Token.objects.get(user__username=username)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
    return client


def admin_client():
    return user_client("admin")


def ndjson_lines(response):
    return [json.loads(line) for line in b"".join(response.streaming_content).splitlines()]


@versioned_fixtures
class TestInstallId(DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.client = admin_client()

    def test_install_id_is_a_persisted_uuid(self):
        first = System_Settings.objects.get(no_cache=True).install_id
        self.assertIsInstance(first, uuid.UUID)
        self.assertEqual(first, System_Settings.objects.get(no_cache=True).install_id)

    def test_api_cannot_change_install_id(self):
        settings_row = System_Settings.objects.get(no_cache=True)
        response = self.client.patch(
            f"/api/v2/system_settings/{settings_row.id}/", {"install_id": str(uuid.uuid4())}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:1000])
        self.assertEqual(settings_row.install_id, System_Settings.objects.get(no_cache=True).install_id)
        self.assertEqual(str(settings_row.install_id), response.json()["install_id"])

    def test_form_has_no_install_id(self):
        self.assertNotIn("install_id", SystemSettingsForm().fields)


@versioned_fixtures
class TestExportSerializers(DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.admin = Dojo_User.objects.get(username="admin")
        request = RequestFactory().get("/")
        request.user = self.admin
        self.context = {"request": request, "max_file_bytes": MAX_FILE_BYTES_DEFAULT}
        self.finding = Finding.objects.filter(test__engagement__product_id=2).order_by("id").first()

    def make_file_upload(self):
        file_upload = FileUpload.objects.create(title="poc.txt", file=ContentFile(b"hello", name="poc.txt"))
        self.addCleanup(file_upload.file.storage.delete, file_upload.file.name)
        return file_upload

    def make_risk_acceptance(self):
        risk_acceptance = Risk_Acceptance.objects.create(
            name="ra", owner=self.admin, path=ContentFile(b"proof", name="waiver.txt"),
        )
        self.addCleanup(risk_acceptance.path.storage.delete, risk_acceptance.path.name)
        return risk_acceptance

    def test_export_file_inlines_small_file(self):
        entry = export_file(self.make_file_upload(), 10)
        self.assertEqual(b"hello", base64.b64decode(entry["data_base64"]))
        self.assertEqual(5, entry["size"])
        self.assertEqual("text/plain", entry["content_type"])
        self.assertEqual("poc.txt", entry["title"])

    def test_export_file_over_cap_has_no_data(self):
        entry = export_file(self.make_file_upload(), 4)
        self.assertIsNone(entry["data_base64"])
        self.assertEqual(5, entry["size"])
        self.assertNotIn("error", entry)

    def test_export_file_marks_a_missing_file(self):
        file_upload = self.make_file_upload()
        file_upload.file.storage.delete(file_upload.file.name)
        entry = export_file(file_upload, MAX_FILE_BYTES_DEFAULT)
        self.assertIsNone(entry["data_base64"])
        self.assertIsNone(entry["size"])
        self.assertEqual("missing", entry["error"])

    def test_export_proof_reads_the_proof(self):
        proof = export_proof(self.make_risk_acceptance(), MAX_FILE_BYTES_DEFAULT)
        self.assertEqual("waiver.txt", proof["filename"])
        self.assertEqual(b"proof", base64.b64decode(proof["data_base64"]))
        without_proof = Risk_Acceptance.objects.create(name="ra without proof", owner=self.admin)
        self.assertIsNone(export_proof(without_proof, MAX_FILE_BYTES_DEFAULT))

    def test_endpoint_entries_carry_uri_and_status(self):
        if locations_enabled():
            finding = Finding.objects.filter(locations__isnull=False).order_by("id").first()
        else:
            finding = Finding.objects.filter(endpoints__isnull=False).order_by("id").first()
        entries = export_endpoint_entries(finding)
        self.assertTrue(entries)
        for entry in entries:
            self.assertEqual({"id", "uri", "location_type", "tags", "status"}, set(entry))
            self.assertIsInstance(entry["uri"], str)
            self.assertTrue(entry["uri"])
            if locations_enabled():
                self.assertIn(entry["status"]["status"], FindingLocationStatus.values)
                self.assertEqual("url", entry["location_type"])
            else:
                self.assertIsInstance(entry["status"]["risk_accepted"], bool)
                self.assertIsNone(entry["location_type"])

    def test_endpoint_entries_empty_for_a_finding_without_endpoints(self):
        finding = Finding.objects.filter(endpoints__isnull=True, locations__isnull=True).order_by("id").first()
        self.assertEqual([], export_endpoint_entries(finding))

    def test_finding_serializer_swaps_only_the_nested_fields(self):
        Risk_Acceptance.objects.get(id=1).accepted_findings.add(self.finding)
        data = ExportFindingSerializer(context=self.context).to_representation(self.finding)
        expected = set(FindingSerializer(context=self.context).fields) - {"accepted_risks", "related_fields"} | {"risk_acceptances"}
        self.assertEqual(expected, set(data))
        self.assertTrue(data["endpoints"])
        for entry in data["endpoints"]:
            self.assertIsInstance(entry, dict)
        self.assertIsInstance(data["files"], list)
        self.assertEqual([1], data["risk_acceptances"])

    def test_risk_acceptance_serializer_shape(self):
        risk_acceptance = self.make_risk_acceptance()
        Engagement.objects.get(id=1).risk_acceptance.add(risk_acceptance)
        risk_acceptance.accepted_findings.add(self.finding)
        risk_acceptance = Risk_Acceptance.objects.prefetch_related("engagement_set", "accepted_findings", "notes").get(
            id=risk_acceptance.id,
        )
        data = ExportRiskAcceptanceSerializer(risk_acceptance, context=self.context).data
        self.assertEqual(1, data["engagement"])
        self.assertEqual("waiver.txt", data["proof"]["filename"])
        self.assertEqual([self.finding.id], data["accepted_findings"])
        self.assertNotIn("path", data)
        self.assertEqual([], data["notes"])

    def test_user_serializer_shape(self):
        user = Dojo_User.objects.get(username="user1")
        UserContactInfo.objects.get_or_create(user=user)
        data = ExportUserSerializer(Dojo_User.objects.select_related("usercontactinfo").get(username="user1")).data
        for key in ("username", "email", "is_superuser", "is_active", "contact_info"):
            self.assertIn(key, data)
        self.assertNotIn("password", data)
        self.assertNotIn("configuration_permissions", data)
        self.assertIsInstance(data["contact_info"], dict)
        self.assertNotIn("user_profile", data["contact_info"])

    def test_product_serializer_nests_the_product_type(self):
        product = Product.objects.get(id=2)
        data = ExportProductSerializer(product, context=self.context).data
        self.assertEqual(product.prod_type.name, data["prod_type"]["name"])
        self.assertNotIn("findings_list", data)
        self.assertNotIn("findings_count", data)


@versioned_fixtures
class TestProductExportStream(DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.client = admin_client()
        self.admin = Dojo_User.objects.get(username="admin")
        self.product = Product.objects.get(id=2)
        self.finding = Finding.objects.filter(test__engagement__product=self.product).order_by("id").first()
        self.finding.notes.add(
            Notes.objects.create(entry="secret", author=Dojo_User.objects.get(username="user1"), private=True),
        )
        file_upload = FileUpload.objects.create(title="poc.txt", file=ContentFile(b"hello", name="poc.txt"))
        self.addCleanup(file_upload.file.storage.delete, file_upload.file.name)
        self.finding.files.add(file_upload)
        DojoMeta.objects.create(finding=self.finding, name="k", value="v")
        BurpRawRequestResponse.objects.create(
            finding=self.finding,
            burpRequestBase64=base64.b64encode(b"GET / HTTP/1.1"),
            burpResponseBase64=base64.b64encode(b"HTTP/1.1 200 OK"),
        )
        Finding_Group.objects.create(name="grp", test=self.finding.test, creator=self.admin).findings.add(self.finding)
        self.ra = Risk_Acceptance.objects.create(name="ra", owner=self.admin, path=ContentFile(b"proof", name="waiver.txt"))
        self.addCleanup(self.ra.path.storage.delete, self.ra.path.name)
        self.ra.accepted_findings.add(self.finding)
        self.finding.test.engagement.risk_acceptance.add(self.ra)
        self.url = reverse("export-product", args=[2])
        self.lines = ndjson_lines(self.client.get(self.url))

    def line_data(self, line_type, object_id, lines=None):
        return next(
            line["data"] for line in lines or self.lines
            if line["type"] == line_type and line["data"]["id"] == object_id
        )

    def test_anonymous_is_403(self):
        response = APIClient().get(self.url)
        self.assertEqual(403, response.status_code, response.content[:1000])
        self.assertEqual("Authentication credentials were not provided.", response.json()["detail"])

    def test_non_superuser_is_403(self):
        client = user_client("user1")
        for url in (self.url, reverse("export-manifest")):
            with self.subTest(url=url):
                response = client.get(url)
                self.assertEqual(403, response.status_code, response.content[:1000])

    def test_unknown_product_is_404(self):
        response = self.client.get(reverse("export-product", args=[999999]))
        self.assertEqual(404, response.status_code, response.content[:1000])

    def test_invalid_max_file_bytes_is_400(self):
        for params in ({"max_file_bytes": "abc"}, {"max_file_bytes": "-1"}):
            with self.subTest(params=params):
                response = self.client.get(self.url, params)
                self.assertEqual(400, response.status_code, response.content[:1000])
                self.assertIn("max_file_bytes", response.json())

    def test_response_streams_ndjson(self):
        response = self.client.get(self.url)
        self.assertTrue(response.streaming)
        self.assertEqual("application/x-ndjson", response["Content-Type"])
        self.assertIn("defectdojo-product-2-export.ndjson", response["Content-Disposition"])

    def test_accept_ndjson_is_not_406(self):
        for accept in ("application/x-ndjson", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"):
            with self.subTest(accept=accept):
                response = self.client.get(self.url, HTTP_ACCEPT=accept)
                self.assertEqual(200, response.status_code)

    def test_empty_product_streams_header_and_end(self):
        self.assertEqual(0, Engagement.objects.filter(product_id=3).count())
        lines = ndjson_lines(self.client.get(reverse("export-product", args=[3])))
        self.assertEqual(["header", "end"], [line["type"] for line in lines])
        self.assertEqual({0}, set(lines[-1]["counts"].values()))

    def test_unicode_survives(self):
        self.finding.notes.add(Notes.objects.create(entry="Bestätigt 🎯", author=self.admin))
        data = self.line_data("finding", self.finding.id, ndjson_lines(self.client.get(self.url)))
        self.assertIn("Bestätigt 🎯", [note["entry"] for note in data["notes"]])

    def test_header_line(self):
        header = self.lines[0]
        self.assertEqual("header", header["type"])
        self.assertEqual(1, header["schema"])
        self.assertEqual(10485760, header["max_file_bytes"])
        self.assertEqual({"version", "install_id", "url", "locations_enabled"}, set(header["source"]))
        self.assertEqual(str(System_Settings.objects.get(no_cache=True).install_id), header["source"]["install_id"])
        self.assertEqual(dojo.__version__, header["source"]["version"])
        self.assertEqual(2, header["product"]["id"])
        self.assertEqual(self.product.prod_type.name, header["product"]["prod_type"]["name"])
        datetime.fromisoformat(header["generated_at"])

    def test_line_order_is_flat_by_type_then_id(self):
        rank = {"engagement": 0, "test": 1, "finding": 2, "risk_acceptance": 3}
        body = self.lines[1:-1]
        ranks = [rank[line["type"]] for line in body]
        self.assertEqual({0, 1, 2, 3}, set(ranks))
        self.assertEqual(sorted(ranks), ranks)
        for line_type in rank:
            ids = [line["data"]["id"] for line in body if line["type"] == line_type]
            self.assertEqual(sorted(set(ids)), ids)
        self.assertEqual("end", self.lines[-1]["type"])

    def test_end_counts_match_the_database_and_the_lines(self):
        counts = self.lines[-1]["counts"]
        body = [line["data"] for line in self.lines[1:-1]]
        findings = [line["data"] for line in self.lines if line["type"] == "finding"]
        self.assertEqual(Engagement.objects.filter(product_id=2).count(), counts["engagements"])
        self.assertEqual(Test.objects.filter(engagement__product_id=2).count(), counts["tests"])
        self.assertEqual(Finding.objects.filter(test__engagement__product_id=2).count(), counts["findings"])
        self.assertEqual(1, counts["risk_acceptances"])
        self.assertEqual(sum(len(data["endpoints"]) for data in findings), counts["endpoints"])
        self.assertEqual(sum(len(data["notes"]) for data in body), counts["notes"])
        self.assertEqual(sum(len(data.get("files", [])) for data in body), counts["files"])
        self.assertEqual(1, counts["finding_groups"])

    def test_finding_line_nested_shapes(self):
        data = self.line_data("finding", self.finding.id)
        self.assertEqual(1, len(data["notes"]))
        self.assertEqual("secret", data["notes"][0]["entry"])
        self.assertTrue(data["notes"][0]["private"])
        self.assertEqual("user1", data["notes"][0]["author"]["username"])
        self.assertEqual(b"hello", base64.b64decode(data["files"][0]["data_base64"]))
        self.assertEqual("grp", data["finding_groups"][0]["name"])
        self.assertEqual([self.ra.id], data["risk_acceptances"])
        self.assertEqual([{"name": "k", "value": "v"}], data["finding_meta"])
        self.assertEqual("GET / HTTP/1.1", data["request_response"]["req_resp"][0]["request"])
        self.assertEqual(self.finding.test_id, data["test"])
        self.assertNotIn("accepted_risks", data)
        self.assertEqual(self.finding.hash_code, data["hash_code"])

    def test_test_line_carries_dedupe_policy(self):
        data = self.line_data("test", self.finding.test_id)
        for key in ("scan_type", "deduplication_algorithm", "hash_code_fields", "engagement", "files", "notes", "finding_groups"):
            self.assertIn(key, data)
        self.assertEqual("grp", data["finding_groups"][0]["name"])

    def test_engagement_line_carries_risk_acceptance_ids(self):
        data = self.line_data("engagement", self.finding.test.engagement_id)
        self.assertIn(self.ra.id, data["risk_acceptance"])
        self.assertIsInstance(data["files"], list)
        self.assertIsInstance(data["notes"], list)

    def test_risk_acceptance_line(self):
        (data,) = [line["data"] for line in self.lines if line["type"] == "risk_acceptance"]
        self.assertEqual("waiver.txt", data["proof"]["filename"])
        self.assertEqual(b"proof", base64.b64decode(data["proof"]["data_base64"]))
        self.assertEqual([self.finding.id], data["accepted_findings"])
        self.assertEqual(self.finding.test.engagement_id, data["engagement"])
        self.assertEqual(self.admin.id, data["owner"])
        self.assertNotIn("path", data)

    def test_file_over_cap_has_no_data(self):
        lines = ndjson_lines(self.client.get(self.url, {"max_file_bytes": 4}))
        data = self.line_data("finding", self.finding.id, lines)
        self.assertIsNone(data["files"][0]["data_base64"])
        self.assertEqual(5, data["files"][0]["size"])
        self.assertEqual(1, lines[-1]["counts"]["files_over_cap"])
        proof = next(line["data"]["proof"] for line in lines if line["type"] == "risk_acceptance")
        self.assertIsNone(proof["data_base64"])

    def test_endpoint_entries_per_mode(self):
        data = next(line["data"] for line in self.lines if line["type"] == "finding" and line["data"]["endpoints"])
        for entry in data["endpoints"]:
            self.assertEqual({"id", "uri", "location_type", "tags", "status"}, set(entry))
            if locations_enabled():
                self.assertEqual("url", entry["location_type"])
                self.assertTrue(entry["status"]["status"])
            else:
                for key in ("mitigated", "false_positive", "out_of_scope", "risk_accepted", "date"):
                    self.assertIn(key, entry["status"])
