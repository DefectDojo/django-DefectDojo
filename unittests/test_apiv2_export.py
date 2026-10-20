import base64
import json
import uuid
from datetime import datetime
from pathlib import Path

from django.core.files.base import ContentFile
from django.test import RequestFactory
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

import dojo
from dojo.endpoint.api.serializer import EndpointStatusSerializer
from dojo.export.api.serializers import (
    MAX_FILE_BYTES_DEFAULT,
    ExportFindingSerializer,
    export_endpoint_entries,
    export_file,
    export_proof,
)
from dojo.export.api.views import COUNT_KEYS
from dojo.finding.api.serializer import FindingSerializer
from dojo.location.api.serializers import LocationFindingReferenceSerializer
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
    Product_Platform,
    Risk_Acceptance,
    System_Settings,
    Test,
    Test_Type,
    UserContactInfo,
)
from dojo.system_settings.ui.forms import SystemSettingsForm
from unittests.dojo_test_case import DojoAPITestCase, versioned_fixtures

RAW_REQUEST = b"GET / HTTP/1.1\r\nX: \xff\xfe\r\n"
RAW_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody\r\n\r\n"


def ndjson_lines(response):
    return [json.loads(line) for line in b"".join(response.streaming_content).splitlines()]


def make_file(case, name):
    file_upload = FileUpload.objects.create(title=name, file=ContentFile(b"hello", name=name))
    case.addClassCleanup(file_upload.file.storage.delete, file_upload.file.name)
    return file_upload


def seed_product(case):
    case.admin = Dojo_User.objects.get(username="admin")
    case.finding = Finding.objects.filter(test__engagement__product_id=2).order_by("id").first()
    test = case.finding.test
    case.finding.notes.add(
        Notes.objects.create(entry="secret", author=Dojo_User.objects.get(username="user1"), private=True),
    )
    case.finding.files.add(make_file(case, "poc.txt"))
    case.owner_files = {}
    for label, owner in (("engagement", test.engagement), ("test", test)):
        owner.notes.add(Notes.objects.create(entry=f"{label} note", author=case.admin))
        case.owner_files[label] = make_file(case, f"{label}.txt")
        owner.files.add(case.owner_files[label])
    DojoMeta.objects.create(finding=case.finding, name="k", value="v")
    BurpRawRequestResponse.objects.create(
        finding=case.finding,
        burpRequestBase64=base64.b64encode(RAW_REQUEST),
        burpResponseBase64=base64.b64encode(RAW_RESPONSE),
    )
    Finding_Group.objects.create(name="grp", test=test, creator=case.admin).findings.add(case.finding)
    case.risk_acceptance = Risk_Acceptance.objects.create(
        name="ra", owner=case.admin, path=ContentFile(b"proof", name="waiver.txt"),
    )
    case.addClassCleanup(case.risk_acceptance.path.storage.delete, case.risk_acceptance.path.name)
    case.risk_acceptance.accepted_findings.add(case.finding)
    test.engagement.risk_acceptance.add(case.risk_acceptance)


@versioned_fixtures
class TestInstallId(DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.login_as_admin()

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
        request = RequestFactory().get("/")
        request.user = Dojo_User.objects.get(username="admin")
        self.context = {"request": request, "max_file_bytes": MAX_FILE_BYTES_DEFAULT}
        self.finding = Finding.objects.filter(test__engagement__product_id=2).order_by("id").first()

    def endpoint_entries(self, finding):
        if locations_enabled():
            return export_endpoint_entries(finding, LocationFindingReferenceSerializer(), locations=True)
        return export_endpoint_entries(finding, EndpointStatusSerializer(), locations=False)

    def test_export_file_inlines_small_file(self):
        file_upload = make_file(self, "poc.txt")
        entry = export_file(file_upload, 10)
        self.assertEqual(b"hello", base64.b64decode(entry["data_base64"]))
        self.assertEqual(5, entry["size"])
        self.assertEqual("text/plain", entry["content_type"])
        self.assertEqual("poc.txt", entry["title"])
        self.assertEqual(Path(file_upload.file.name).name, entry["filename"])

    def test_export_file_marks_a_missing_file(self):
        file_upload = make_file(self, "poc.txt")
        file_upload.file.storage.delete(file_upload.file.name)
        entry = export_file(file_upload, MAX_FILE_BYTES_DEFAULT)
        self.assertIsNone(entry["data_base64"])
        self.assertIsNone(entry["size"])
        self.assertEqual("missing", entry["error"])

    def test_export_file_marks_an_empty_name_missing(self):
        entry = export_file(FileUpload(title="empty", file=""), MAX_FILE_BYTES_DEFAULT)
        self.assertIsNone(entry["size"])
        self.assertEqual("missing", entry["error"])

    def test_export_proof_is_none_without_a_proof(self):
        risk_acceptance = Risk_Acceptance.objects.create(name="ra without proof", owner=self.context["request"].user)
        self.assertIsNone(export_proof(risk_acceptance, MAX_FILE_BYTES_DEFAULT))

    def test_endpoint_entries_carry_uri_and_status(self):
        if locations_enabled():
            finding = Finding.objects.filter(locations__isnull=False).order_by("id").first()
        else:
            finding = Finding.objects.filter(endpoints__isnull=False).order_by("id").first()
        entries = self.endpoint_entries(finding)
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
        self.assertEqual([], self.endpoint_entries(finding))

    def test_finding_serializer_swaps_only_the_nested_fields(self):
        Risk_Acceptance.objects.get(id=1).accepted_findings.add(self.finding)
        data = ExportFindingSerializer(context=self.context).to_representation(self.finding)
        expected = set(FindingSerializer(context=self.context).fields) - {"accepted_risks", "related_fields", "request_response"}
        expected |= {"risk_acceptances", "request_response_pairs"}
        self.assertEqual(expected, set(data))
        self.assertTrue(data["endpoints"])
        for entry in data["endpoints"]:
            self.assertIsInstance(entry, dict)
        self.assertIsInstance(data["files"], list)
        self.assertEqual([1], data["risk_acceptances"])


@versioned_fixtures
class TestProductExportStream(DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        seed_product(cls)
        cls.url = reverse("export-product", args=[2])
        client = APIClient()
        client.force_authenticate(cls.admin)
        cls.lines = ndjson_lines(client.get(cls.url))

    def setUp(self):
        super().setUp()
        self.login_as_admin()

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
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.get(user__username='user1').key}")
        for url in (self.url, reverse("export-manifest")):
            with self.subTest(url=url):
                response = client.get(url)
                self.assertEqual(403, response.status_code, response.content[:1000])

    def test_unknown_product_is_404(self):
        response = self.client.get(reverse("export-product", args=[999999]))
        self.assertEqual(404, response.status_code, response.content[:1000])

    def test_invalid_max_file_bytes_is_400(self):
        for value in ("abc", "-1", "1" * 5000):
            with self.subTest(value=value[:10]):
                response = self.client.get(self.url, {"max_file_bytes": value})
                self.assertEqual(400, response.status_code, response.content[:1000])
                self.assertIn("max_file_bytes", response.json())

    def test_empty_max_file_bytes_uses_the_default(self):
        response = self.client.get(self.url, {"max_file_bytes": ""})
        self.assertEqual(200, response.status_code)
        self.assertEqual(MAX_FILE_BYTES_DEFAULT, ndjson_lines(response)[0]["max_file_bytes"])

    def test_response_streams_ndjson(self):
        response = self.client.get(self.url)
        self.assertTrue(response.streaming)
        self.assertEqual("application/x-ndjson", response["Content-Type"])
        self.assertIn("defectdojo-product-2-export.ndjson", response["Content-Disposition"])
        self.assertEqual("no", response["X-Accel-Buffering"])

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

    def test_non_finite_float_is_null(self):
        Finding.objects.filter(pk=self.finding.pk).update(cvssv3_score=float("nan"))
        lines = ndjson_lines(self.client.get(self.url))
        self.assertIsNone(self.line_data("finding", self.finding.id, lines)["cvssv3_score"])
        self.assertEqual("end", lines[-1]["type"])

    def test_header_line(self):
        header = self.lines[0]
        self.assertEqual("header", header["type"])
        self.assertEqual(1, header["schema"])
        self.assertEqual(10485760, header["max_file_bytes"])
        self.assertEqual({"version", "install_id", "url", "locations_enabled"}, set(header["source"]))
        self.assertEqual(str(System_Settings.objects.get(no_cache=True).install_id), header["source"]["install_id"])
        self.assertEqual(dojo.__version__, header["source"]["version"])
        self.assertEqual(2, header["product"]["id"])
        self.assertEqual(Product.objects.get(id=2).prod_type.name, header["product"]["prod_type"]["name"])
        self.assertNotIn("findings_list", header["product"])
        self.assertNotIn("findings_count", header["product"])
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
        # The fixture has 3 notes and no files on product 2. seed_product adds 3 notes and 3 files.
        self.assertEqual(6, counts["notes"])
        self.assertEqual(3, counts["files"])
        self.assertEqual(1, counts["finding_groups"])

    def test_finding_line_nested_shapes(self):
        data = self.line_data("finding", self.finding.id)
        self.assertEqual(1, len(data["notes"]))
        self.assertEqual("secret", data["notes"][0]["entry"])
        self.assertTrue(data["notes"][0]["private"])
        self.assertEqual("user1", data["notes"][0]["author"]["username"])
        self.assertEqual(b"hello", base64.b64decode(data["files"][0]["data_base64"]))
        self.assertEqual("grp", data["finding_groups"][0]["name"])
        self.assertEqual([self.risk_acceptance.id], data["risk_acceptances"])
        self.assertEqual([{"name": "k", "value": "v"}], data["finding_meta"])
        (pair,) = data["request_response_pairs"]
        self.assertEqual(base64.b64encode(RAW_REQUEST).decode(), pair["burpRequestBase64"])
        self.assertEqual(base64.b64encode(RAW_RESPONSE).decode(), pair["burpResponseBase64"])
        self.assertNotIn("request_response", data)
        self.assertEqual(self.finding.test_id, data["test"])
        self.assertNotIn("accepted_risks", data)
        self.assertEqual(self.finding.hash_code, data["hash_code"])

    def test_test_line(self):
        data = self.line_data("test", self.finding.test_id)
        for key in ("scan_type", "deduplication_algorithm", "hash_code_fields", "engagement"):
            self.assertIn(key, data)
        self.assertEqual("grp", data["finding_groups"][0]["name"])
        self.assertEqual("test note", data["notes"][0]["entry"])
        self.assertEqual(Path(self.owner_files["test"].file.name).name, data["files"][0]["filename"])

    def test_engagement_line(self):
        data = self.line_data("engagement", self.finding.test.engagement_id)
        self.assertIn(self.risk_acceptance.id, data["risk_acceptance"])
        self.assertEqual("engagement note", data["notes"][0]["entry"])
        self.assertEqual(Path(self.owner_files["engagement"].file.name).name, data["files"][0]["filename"])

    def test_risk_acceptance_line(self):
        (data,) = [line["data"] for line in self.lines if line["type"] == "risk_acceptance"]
        self.assertEqual("waiver.txt", data["proof"]["filename"])
        self.assertEqual(b"proof", base64.b64decode(data["proof"]["data_base64"]))
        self.assertEqual([self.finding.id], data["accepted_findings"])
        self.assertEqual(self.finding.test.engagement_id, data["engagement"])
        self.assertEqual(self.admin.id, data["owner"])
        self.assertEqual([], data["notes"])
        self.assertNotIn("path", data)

    def test_file_over_cap_has_no_data(self):
        lines = ndjson_lines(self.client.get(self.url, {"max_file_bytes": 4}))
        entry = self.line_data("finding", self.finding.id, lines)["files"][0]
        self.assertIsNone(entry["data_base64"])
        self.assertEqual(5, entry["size"])
        self.assertNotIn("error", entry)
        self.assertEqual(3, lines[-1]["counts"]["files_over_cap"])
        proof = next(line["data"]["proof"] for line in lines if line["type"] == "risk_acceptance")
        self.assertIsNone(proof["data_base64"])


@versioned_fixtures
class TestExportManifest(DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        seed_product(cls)
        UserContactInfo.objects.get_or_create(user=Dojo_User.objects.get(username="user1"))
        cls.url = reverse("export-manifest")
        client = APIClient()
        client.force_authenticate(cls.admin)
        cls.manifest = client.get(cls.url).json()

    def setUp(self):
        super().setUp()
        self.login_as_admin()

    def test_manifest_top_level_keys(self):
        self.assertEqual(
            {
                "schema", "generated_at", "source", "max_file_bytes", "token", "scan_types", "reference",
                "product_types", "products", "totals",
            },
            set(self.manifest),
        )
        self.assertEqual(1, self.manifest["schema"])
        self.assertEqual(str(System_Settings.objects.get(no_cache=True).install_id), self.manifest["source"]["install_id"])
        for entry in self.manifest["products"]:
            self.assertEqual(set(COUNT_KEYS), set(entry["counts"]))

    def test_token_block(self):
        token = self.client.get(self.url).json()["token"]
        self.assertIsInstance(token["expires_at"], str | None)
        self.assertEqual({"username": "admin", "is_superuser": True, "expires_at": token["expires_at"]}, token)

    def test_product_type_counts_roll_up(self):
        products = self.manifest["products"]
        for product_type in self.manifest["product_types"]:
            members = [entry for entry in products if entry["prod_type"] == product_type["id"]]
            self.assertEqual(sum(entry["counts"]["findings"] for entry in members), product_type["counts"]["findings"])
            self.assertEqual(
                Product.objects.filter(prod_type_id=product_type["id"]).count(), product_type["counts"]["products"],
            )
        self.assertEqual(sum(entry["counts"]["findings"] for entry in products), self.manifest["totals"]["findings"])

    def test_counts_match_the_stream(self):
        first, second = Finding.objects.filter(test__engagement__product_id=2).order_by("id")[:2]
        note = Notes.objects.create(entry="shared", author=self.admin)
        file_upload = make_file(self, "shared.txt")
        for finding in (first, second):
            finding.notes.add(note)
            finding.files.add(file_upload)
        first.test.files.add(file_upload)
        self.risk_acceptance.notes.add(note)
        Engagement.objects.filter(product_id=2).exclude(id=first.test.engagement_id).first().risk_acceptance.add(
            self.risk_acceptance,
        )
        for params in ({}, {"max_file_bytes": 4}):
            with self.subTest(params=params):
                counts = self.get_results_by_id(self.client.get(self.url, params).json()["products"], 2)["counts"]
                end = ndjson_lines(self.client.get(reverse("export-product", args=[2]), params))[-1]["counts"]
                for key in ("engagements", "tests", "findings", "notes", "files", "files_over_cap", "risk_acceptances"):
                    self.assertEqual(end[key], counts[key], key)
                # Every seeded file holds 5 bytes, so all are over a cap of 4 and none are over the default.
                self.assertEqual(counts["files"] if params else 0, counts["files_over_cap"])
                self.assertEqual(1, counts["finding_groups"])

    def test_reference_data(self):
        reference = self.manifest["reference"]
        self.assertEqual(
            {
                "sla_configurations", "development_environments", "regulations", "test_types", "note_types",
                "product_platforms", "product_lifecycles", "product_origins", "users",
            },
            set(reference),
        )
        self.assertEqual(
            list(Product_Platform.objects.order_by("id").values_list("value", flat=True)),
            [platform["value"] for platform in reference["product_platforms"]],
        )
        self.assertEqual(Dojo_User.objects.count(), len(reference["users"]))
        user1 = next(user for user in reference["users"] if user["username"] == "user1")
        self.assertNotIn("password", user1)
        self.assertNotIn("configuration_permissions", user1)
        self.assertNotIn("user_profile", user1["contact_info"])
        self.assertIn("email", user1)
        self.assertFalse(user1["is_superuser"])
        self.assertEqual(Test_Type.objects.count(), len(reference["test_types"]))

    def test_scan_types_are_distinct_and_sorted(self):
        self.assertEqual(
            sorted(set(Test.objects.exclude(scan_type=None).values_list("scan_type", flat=True))),
            self.manifest["scan_types"],
        )

    def test_products_and_types_sorted_by_id(self):
        for key in ("products", "product_types"):
            ids = [entry["id"] for entry in self.manifest[key]]
            self.assertTrue(ids)
            self.assertEqual(sorted(set(ids)), ids)
