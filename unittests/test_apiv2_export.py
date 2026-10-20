import base64
import json
import uuid

from django.core.files.base import ContentFile
from django.test import RequestFactory
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

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
    Dojo_User,
    Engagement,
    FileUpload,
    Finding,
    Product,
    Risk_Acceptance,
    System_Settings,
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
