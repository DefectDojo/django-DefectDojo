import base64
import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

import pghistory
from auditlog.models import LogEntry
from django.apps import apps
from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.core.files.base import ContentFile
from django.db import connection
from django.db.models import Q
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from drf_spectacular.generators import SchemaGenerator
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

import dojo
from dojo.endpoint.api.serializer import EndpointStatusSerializer
from dojo.endpoint.models import Endpoint_Status
from dojo.export.api.serializers import (
    MAX_FILE_BYTES_DEFAULT,
    ExportEngagementSerializer,
    ExportFindingSerializer,
    ExportRiskAcceptanceSerializer,
    export_endpoint_entries,
    export_file,
    export_proof,
    render_datetime,
)
from dojo.export.api.views import ACTIONS_PER_LINE, AUDIT_MODELS, COUNT_KEYS
from dojo.finding.api.serializer import FindingSerializer
from dojo.location.api.serializers import LocationFindingReferenceSerializer
from dojo.location.feature import locations_enabled
from dojo.location.models import LocationFindingReference
from dojo.location.status import FindingLocationStatus
from dojo.models import (
    Announcement,
    BannerConf,
    BurpRawRequestResponse,
    Check_List,
    Contact,
    Dojo_User,
    DojoMeta,
    Engagement,
    Engagement_Presets,
    FileUpload,
    Finding,
    Finding_Group,
    Finding_Template,
    Network_Locations,
    Notes,
    Product,
    Product_API_Scan_Configuration,
    Product_Platform,
    Report_Type,
    Risk_Acceptance,
    System_Settings,
    Test,
    Test_Import,
    Test_Import_Finding_Action,
    Test_Type,
    UserContactInfo,
)
from dojo.system_settings.ui.forms import SystemSettingsForm
from dojo.tool_config.models import Tool_Configuration
from dojo.tool_type.models import Tool_Type
from unittests.dojo_test_case import DojoAPITestCase, versioned_fixtures

FindingEvent = apps.get_model("dojo", "FindingEvent")
RAW_REQUEST = b"GET / HTTP/1.1\r\nX: \xff\xfe\r\n"
RAW_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody\r\n\r\n"


def ndjson_lines(response):
    return [json.loads(line) for line in b"".join(response.streaming_content).splitlines()]


def make_file(case, name, content=b"hello"):
    file_upload = FileUpload.objects.create(title=name, file=ContentFile(content, name=name))
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
    case.risk_acceptance.notes.add(Notes.objects.create(entry="ra note", author=case.admin))


def seed_check_lists(case):
    case.checked_engagement = case.finding.test.engagement
    case.checked_findings = list(Finding.objects.filter(test__engagement__product_id=2).order_by("id")[:2])
    first, second = case.checked_findings
    case.foreign_finding = Finding.objects.exclude(test__engagement__product_id=2).order_by("id").first()
    case.check_list = Check_List.objects.create(
        engagement=case.checked_engagement,
        session_management="Pass",
        encryption_crypto="Fail",
        configuration_management="N/A",
        authentication="Pass",
        authorization_and_access_control="Fail",
        data_input_sanitization_validation="N/A",
        sensitive_data="Pass",
        other="Fail",
    )
    case.check_list.session_issues.add(first, second)
    case.check_list.other_issues.add(second)
    case.check_list.data_issues.add(case.foreign_finding)
    Check_List.objects.create(engagement=case.checked_engagement, session_management="Fail").session_issues.add(first)


SHIPPED_DEDUPLICATION_MAPS = {
    "HASHCODE_FIELDS_PER_SCANNER_SHIPPED": "HASHCODE_FIELDS_PER_SCANNER",
    "DEDUPLICATION_ALGORITHM_PER_PARSER_SHIPPED": "DEDUPLICATION_ALGORITHM_PER_PARSER",
    "HASHCODE_ALLOWS_NULL_CWE_SHIPPED": "HASHCODE_ALLOWS_NULL_CWE",
}


class TestShippedDeduplicationSettings(SimpleTestCase):
    def test_each_shipped_map_is_a_separate_copy_of_its_map(self):
        for shipped_name, name in SHIPPED_DEDUPLICATION_MAPS.items():
            with self.subTest(shipped_name):
                shipped = getattr(settings, shipped_name)
                self.assertTrue(shipped)
                self.assertIsNot(getattr(settings, name), shipped)

    def test_changing_a_map_leaves_the_shipped_copy_as_it_was(self):
        before = {name: json.dumps(getattr(settings, name), sort_keys=True) for name in SHIPPED_DEDUPLICATION_MAPS}
        with override_settings(
            HASHCODE_FIELDS_PER_SCANNER={"Only Scan": ["title"]},
            DEDUPLICATION_ALGORITHM_PER_PARSER={"Only Scan": "legacy"},
            HASHCODE_ALLOWS_NULL_CWE={"Only Scan": False},
        ):
            for name in SHIPPED_DEDUPLICATION_MAPS:
                self.assertEqual(before[name], json.dumps(getattr(settings, name), sort_keys=True))
        scan_type = next(iter(settings.HASHCODE_FIELDS_PER_SCANNER_SHIPPED))
        live = settings.HASHCODE_FIELDS_PER_SCANNER[scan_type]
        live.append("mitigation")
        try:
            self.assertEqual(before["HASHCODE_FIELDS_PER_SCANNER_SHIPPED"], json.dumps(settings.HASHCODE_FIELDS_PER_SCANNER_SHIPPED, sort_keys=True))
        finally:
            live.pop()


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

    def test_export_file_marks_a_name_the_server_cannot_encode_missing(self):
        file_upload = make_file(self, "poc.txt")
        refused = UnicodeEncodeError("ascii", "\u00fc", 0, 1, "ordinal not in range(128)")
        with mock.patch.object(file_upload.file.storage, "size", side_effect=refused):
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

    def line_files(self, *contents, max_file_bytes=MAX_FILE_BYTES_DEFAULT):
        engagement = self.finding.test.engagement
        for index, content in enumerate(contents):
            engagement.files.add(make_file(self, f"line{index}.txt", content))
        context = {**self.context, "max_file_bytes": max_file_bytes}
        return ExportEngagementSerializer(context=context).get_files(engagement)

    def test_a_line_under_the_inline_budget_is_unchanged(self):
        entries = self.line_files(b"a", b"b", b"c")
        self.assertEqual([b"a", b"b", b"c"], [base64.b64decode(entry["data_base64"]) for entry in entries])
        self.assertFalse(any("error" in entry for entry in entries))

    def test_a_line_past_the_inline_budget_marks_the_later_files(self):
        # "hello" is 8 characters of base64 text.
        with mock.patch("dojo.export.api.serializers.MAX_INLINE_BYTES_PER_LINE", 16):
            entries = self.line_files(b"hello", b"hello", b"hello")
        self.assertEqual([False, False, True], ["error" in entry for entry in entries])
        self.assertIsNotNone(entries[1]["data_base64"])
        self.assertIsNone(entries[2]["data_base64"])
        self.assertEqual("line_cap", entries[2]["error"])
        self.assertEqual(5, entries[2]["size"])
        self.assertEqual("text/plain", entries[2]["content_type"])

    def test_a_small_file_still_fits_after_a_marked_one(self):
        with mock.patch("dojo.export.api.serializers.MAX_INLINE_BYTES_PER_LINE", 20):
            entries = self.line_files(b"hello", b"x" * 30, b"hello")
        self.assertEqual([None, "line_cap", None], [entry.get("error") for entry in entries])
        self.assertIsNone(entries[1]["data_base64"])
        self.assertEqual(30, entries[1]["size"])
        self.assertIsNotNone(entries[2]["data_base64"])

    def test_a_file_over_the_file_cap_does_not_use_the_inline_budget(self):
        with mock.patch("dojo.export.api.serializers.MAX_INLINE_BYTES_PER_LINE", 8):
            entries = self.line_files(b"x" * 30, b"hello", max_file_bytes=10)
        self.assertIsNone(entries[0]["data_base64"])
        self.assertNotIn("error", entries[0])
        self.assertIsNotNone(entries[1]["data_base64"])

    def test_a_proof_past_the_inline_budget_is_marked(self):
        risk_acceptance = Risk_Acceptance.objects.create(
            name="ra with proof", owner=self.context["request"].user, path=ContentFile(b"proof", name="waiver.txt"),
        )
        self.addCleanup(risk_acceptance.path.storage.delete, risk_acceptance.path.name)
        serializer = ExportRiskAcceptanceSerializer(context=self.context)
        self.assertIsNotNone(serializer.get_proof(risk_acceptance)["data_base64"])
        with mock.patch("dojo.export.api.serializers.MAX_INLINE_BYTES_PER_LINE", 4):
            proof = serializer.get_proof(risk_acceptance)
        self.assertIsNone(proof["data_base64"])
        self.assertEqual("line_cap", proof["error"])
        self.assertEqual(5, proof["size"])

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
        cls.preset = Engagement_Presets.objects.create(title="Quarterly", notes="n", scope="s", product_id=2)
        cls.preset.test_type.add(*Test_Type.objects.filter(name__in=["ZAP Scan", "BURP Scan"]))
        cls.preset.network_locations.add(Network_Locations.objects.create(location="VPN"))
        Engagement_Presets.objects.create(title="Other", scope="", product_id=1)
        Product_API_Scan_Configuration.objects.create(product_id=1, tool_configuration_id=3, service_key_1="other")
        seed_check_lists(cls)
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
        for url in (self.url, reverse("export-manifest")):
            with self.subTest(url=url):
                response = APIClient().get(url)
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

    def test_max_file_bytes_has_a_ceiling_of_100_mib(self):
        for url in (self.url, reverse("export-manifest")):
            with self.subTest(url=url):
                response = self.client.get(url, {"max_file_bytes": 104857601})
                self.assertEqual(400, response.status_code, response.content[:1000])
                self.assertIn("max_file_bytes", response.json())
        response = self.client.get(self.url, {"max_file_bytes": 104857600})
        self.assertEqual(104857600, ndjson_lines(response)[0]["max_file_bytes"])

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

    def test_line_separator_characters_are_escaped(self):
        # Regression: U+0085 went out raw, so str.splitlines() cut the line in two.
        entry = "a\u0085b\u2028c\u2029d"
        self.finding.notes.add(Notes.objects.create(entry=entry, author=self.admin))
        body = b"".join(self.client.get(self.url).streaming_content)
        for raw in (b"\xc2\x85", b"\xe2\x80\xa8", b"\xe2\x80\xa9"):
            self.assertNotIn(raw, body)
        self.assertEqual(body.decode().split("\n")[:-1], body.decode().splitlines())
        data = self.line_data("finding", self.finding.id, [json.loads(line) for line in body.splitlines()])
        self.assertIn(entry, [note["entry"] for note in data["notes"]])

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

    def test_header_carries_engagement_presets_and_api_scan_configurations(self):
        header = self.lines[0]
        (preset,) = header["engagement_presets"]
        self.assertEqual(self.preset.id, preset["id"])
        self.assertEqual(("Quarterly", "n", "s"), (preset["title"], preset["notes"], preset["scope"]))
        self.assertEqual(["BURP Scan", "ZAP Scan"], sorted(preset["test_type"]))
        self.assertEqual(["VPN"], preset["network_locations"])
        self.assertNotIn("product", preset)
        self.assertFalse({"archived_at", "archive_batch"} & preset.keys())
        self.assertEqual(
            [{"id": 1, "tool_configuration": 3, "service_key_1": "dojo_sonar_key", "service_key_2": None, "service_key_3": None}],
            header["api_scan_configurations"],
        )
        empty = ndjson_lines(self.client.get(reverse("export-product", args=[3])))[0]
        self.assertEqual(([], []), (empty["engagement_presets"], empty["api_scan_configurations"]))

    def test_the_stream_adds_no_new_line_type(self):
        self.assertEqual(
            {"header", "engagement", "test", "finding", "risk_acceptance", "end"},
            {line["type"] for line in self.lines},
        )

    def test_line_order_is_flat_by_type_then_id(self):
        rank = {"engagement": 0, "test": 1, "finding": 2, "risk_acceptance": 3}
        body = self.lines[1:-1]
        ranks = [rank[line["type"]] for line in body]
        self.assertEqual({0, 1, 2, 3}, set(ranks))
        self.assertEqual(sorted(ranks), ranks)
        for line_type in rank:
            rows = [line["data"] for line in body if line["type"] == line_type]
            keys = [(row["test"], row["id"]) for row in rows] if line_type == "finding" else [row["id"] for row in rows]
            self.assertEqual(sorted(set(keys)), keys)
        self.assertEqual("end", self.lines[-1]["type"])

    def test_findings_group_by_test_even_when_ids_interleave(self):
        first_test = Test.objects.filter(engagement__product_id=2, finding__isnull=False).order_by("id").first()
        late = Finding.objects.create(title="late", test=first_test, reporter=self.admin, severity="Low")
        tests = [line["data"]["test"] for line in ndjson_lines(self.client.get(self.url)) if line["type"] == "finding"]
        self.assertEqual(sorted(tests), tests)
        self.assertGreater(late.id, max(Finding.objects.exclude(id=late.id).values_list("id", flat=True)))

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
        status_model = LocationFindingReference if locations_enabled() else Endpoint_Status
        self.assertEqual(status_model.objects.filter(finding__test__engagement__product_id=2).count(), counts["endpoints"])
        # The fixture has 3 notes and no files on product 2. seed_product adds 4 notes and 3 files.
        self.assertEqual(7, counts["notes"])
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

    def test_engagement_line_carries_the_lowest_check_list(self):
        first, second = self.checked_findings
        data = self.line_data("engagement", self.checked_engagement.id)
        self.assertEqual(
            {
                "id": self.check_list.id,
                "session_management": "Pass",
                "encryption_crypto": "Fail",
                "configuration_management": "N/A",
                "authentication": "Pass",
                "authorization_and_access_control": "Fail",
                "data_input_sanitization_validation": "N/A",
                "sensitive_data": "Pass",
                "other": "Fail",
                "session_issues": [first.id, second.id],
                "crypto_issues": [],
                "config_issues": [],
                "auth_issues": [],
                "author_issues": [],
                "data_issues": [self.foreign_finding.id],
                "sensitive_issues": [],
                "other_issues": [second.id],
            },
            data["check_list_detail"],
        )
        self.assertNotIn("archived_at", data["check_list_detail"])
        self.assertNotIn("archive_batch", data["check_list_detail"])
        self.assertIsInstance(data["check_list"], bool)
        self.assertTrue(data["check_list"])

    def test_engagement_line_without_a_check_list_is_null(self):
        other = Engagement.objects.filter(product_id=2).exclude(id=self.checked_engagement.id).order_by("id").first()
        self.assertFalse(Check_List.objects.filter(engagement=other).exists())
        data = self.line_data("engagement", other.id)
        self.assertIsNone(data["check_list_detail"])
        self.assertIsInstance(data["check_list"], bool)
        self.assertEqual(other.check_list, data["check_list"])

    def test_engagement_check_list_flag_stays_a_boolean(self):
        Engagement.objects.filter(id=self.checked_engagement.id).update(check_list=False)
        data = self.line_data("engagement", self.checked_engagement.id, ndjson_lines(self.client.get(self.url)))
        self.assertIsInstance(data["check_list"], bool)
        self.assertFalse(data["check_list"])
        self.assertEqual(self.check_list.id, data["check_list_detail"]["id"])

    def test_risk_acceptance_line(self):
        (data,) = [line["data"] for line in self.lines if line["type"] == "risk_acceptance"]
        self.assertEqual(Path(self.risk_acceptance.path.name).name, data["proof"]["filename"])
        self.assertEqual(b"proof", base64.b64decode(data["proof"]["data_base64"]))
        self.assertEqual([self.finding.id], data["accepted_findings"])
        self.assertEqual(self.finding.test.engagement_id, data["engagement"])
        self.assertEqual(self.admin.id, data["owner"])
        self.assertEqual(["ra note"], [note["entry"] for note in data["notes"]])
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

    def test_file_at_cap_is_inlined(self):
        lines = ndjson_lines(self.client.get(self.url, {"max_file_bytes": 5}))
        entry = self.line_data("finding", self.finding.id, lines)["files"][0]
        self.assertEqual(b"hello", base64.b64decode(entry["data_base64"]))
        self.assertEqual(0, lines[-1]["counts"]["files_over_cap"])
        proof = next(line["data"]["proof"] for line in lines if line["type"] == "risk_acceptance")
        self.assertEqual(b"proof", base64.b64decode(proof["data_base64"]))

    def test_a_file_past_the_inline_budget_is_not_counted_over_cap(self):
        self.finding.files.add(make_file(self, "second.txt"))
        with mock.patch("dojo.export.api.serializers.MAX_INLINE_BYTES_PER_LINE", 8):
            lines = ndjson_lines(self.client.get(self.url))
        first, second = self.line_data("finding", self.finding.id, lines)["files"]
        self.assertIsNotNone(first["data_base64"])
        self.assertIsNone(second["data_base64"])
        self.assertEqual("line_cap", second["error"])
        self.assertEqual(4, lines[-1]["counts"]["files"])
        self.assertEqual(0, lines[-1]["counts"]["files_over_cap"])

    def test_risk_acceptance_linked_only_through_a_finding_crosses(self):
        # Regression: an acceptance with no engagement link got no line while the finding line named its id.
        unlinked = Risk_Acceptance.objects.create(name="unlinked", owner=self.admin)
        unlinked.accepted_findings.add(self.finding)
        unlinked.notes.add(Notes.objects.create(entry="unlinked note", author=self.admin))
        lines = ndjson_lines(self.client.get(self.url))
        self.assertIn(unlinked.id, [line["data"]["id"] for line in lines if line["type"] == "risk_acceptance"])
        data = self.line_data("risk_acceptance", unlinked.id, lines)
        self.assertIsNone(data["engagement"])
        self.assertEqual(["unlinked note"], [note["entry"] for note in data["notes"]])
        self.assertIn(unlinked.id, self.line_data("finding", self.finding.id, lines)["risk_acceptances"])
        before = self.lines[-1]["counts"]
        self.assertEqual(before["risk_acceptances"] + 1, lines[-1]["counts"]["risk_acceptances"])
        self.assertEqual(before["notes"] + 1, lines[-1]["counts"]["notes"])

    def test_schema_types_the_product_id_as_an_integer(self):
        schema = SchemaGenerator().get_schema(request=None, public=True)
        parameters = schema["paths"]["/api/v2/export/products/{id}/"]["get"]["parameters"]
        self.assertEqual(["integer"], [parameter["schema"]["type"] for parameter in parameters if parameter["in"] == "path"])


@versioned_fixtures
class TestExportImportHistory(DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        cls.admin = Dojo_User.objects.get(username="admin")
        test = Test_Import.objects.get(id=6829).test
        findings = [Finding.objects.create(title=f"h{i}", test=test, reporter=cls.admin, severity="Low") for i in range(4)]
        cls.reimport = Test_Import.objects.create(
            test=test,
            type="reimport",
            version="1.2",
            build_id="b7",
            commit_hash="abc123",
            branch_tag="main",
            import_settings={"close_old_findings": True, "tags": ["a"]},
        )
        cls.empty_import = Test_Import.objects.create(test=test, type="import")
        # The reimport's actions are created out of finding order, so action id order differs from finding id order.
        for finding, action in zip((findings[2], findings[0], findings[3], findings[1]), "CRUN", strict=True):
            Test_Import_Finding_Action.objects.create(test_import=cls.reimport, finding=finding, action=action)
        Test_Import.objects.filter(id=cls.reimport.id).update(
            created=datetime(2025, 3, 4, 5, 6, 7, 123456, tzinfo=UTC), modified=datetime(2025, 3, 5, 6, 7, 8, 654321, tzinfo=UTC),
        )
        for number, action in enumerate(Test_Import_Finding_Action.objects.filter(test_import=cls.reimport).order_by("id"), start=1):
            Test_Import_Finding_Action.objects.filter(id=action.id).update(
                created=datetime(2025, 3, 4, 5, 6, number, 1000 * number, tzinfo=UTC),
                modified=datetime(2025, 3, 5, 6, 7, number, 1000 * number, tzinfo=UTC),
            )
        cls.reimport.refresh_from_db()
        accepted = Risk_Acceptance.objects.create(name="ra", owner=cls.admin)
        accepted.accepted_findings.add(findings[0])

    def setUp(self):
        super().setUp()
        self.login_as_admin()

    def export(self, product_id=2, **params):
        return ndjson_lines(self.client.get(reverse("export-product", args=[product_id]), params))

    def end_line(self, product_id=2, **params):
        return self.export(product_id, **params)[-1]

    def import_line(self, import_id, lines):
        return next(line["data"] for line in lines if line["type"] == "test_import" and line["data"]["id"] == import_id)

    def expected_actions(self, import_id):
        rows = Test_Import_Finding_Action.objects.filter(test_import_id=import_id).order_by("id")
        return [[row.finding_id, row.action, render_datetime(row.created), render_datetime(row.modified)] for row in rows]

    def test_the_stream_has_no_history_lines_by_default(self):
        lines = self.export()
        self.assertEqual({"header", "engagement", "test", "finding", "risk_acceptance", "end"}, {line["type"] for line in lines})
        self.assertEqual(set(COUNT_KEYS), set(lines[-1]["counts"]))

    def test_import_history_follows_the_risk_acceptances(self):
        kinds = [line["type"] for line in self.export(import_history="true")]
        first = kinds.index("test_import")
        self.assertLess(max(i for i, kind in enumerate(kinds) if kind == "risk_acceptance"), first)
        self.assertEqual("end", kinds[-1])
        self.assertEqual({"test_import", "test_import_actions"}, set(kinds[first:-1]))

    def test_an_import_line_carries_the_source_values_and_dates(self):
        data = self.import_line(self.reimport.id, self.export(import_history="true"))
        self.assertEqual(
            {"id", "test", "type", "version", "build_id", "commit_hash", "branch_tag", "import_settings", "created", "modified"},
            set(data),
        )
        self.assertEqual(
            ("reimport", "1.2", "b7", "abc123", "main", self.reimport.test_id),
            (data["type"], data["version"], data["build_id"], data["commit_hash"], data["branch_tag"], data["test"]),
        )
        self.assertEqual(self.reimport.import_settings, data["import_settings"])
        for key in ("created", "modified"):
            self.assertEqual(render_datetime(getattr(self.reimport, key)), data[key])
            self.assertEqual(getattr(self.reimport, key), datetime.fromisoformat(data[key]))
        self.assertNotEqual(data["created"], data["modified"])

    def test_each_import_is_followed_by_its_actions_in_test_then_id_order(self):
        lines = self.export(import_history="true")
        body = [line for line in lines if line["type"] in {"test_import", "test_import_actions"}]
        imports = [line["data"]["id"] for line in body if line["type"] == "test_import"]
        self.assertEqual([6829, self.reimport.id, self.empty_import.id, 6830], imports)
        owner, actions = None, {}
        for line in body:
            if line["type"] == "test_import":
                owner = line["data"]["id"]
            else:
                self.assertEqual(owner, line["data"]["test_import"])
                actions.setdefault(owner, []).extend(line["data"]["actions"])
        with_actions = [import_id for import_id in imports if import_id != self.empty_import.id]
        self.assertEqual({import_id: self.expected_actions(import_id) for import_id in with_actions}, actions)
        self.assertEqual(4, len(actions[self.reimport.id]))

    def test_an_import_with_more_actions_than_one_line_spans_lines(self):
        self.assertEqual(10000, ACTIONS_PER_LINE)
        with mock.patch("dojo.export.api.views.ACTIONS_PER_LINE", 3):
            lines = self.export(import_history="true")
        reimport_lines = [
            line["data"]["actions"]
            for line in lines
            if line["type"] == "test_import_actions" and line["data"]["test_import"] == self.reimport.id
        ]
        self.assertEqual([3, 1], [len(actions) for actions in reimport_lines])
        self.assertEqual(self.expected_actions(self.reimport.id), [action for actions in reimport_lines for action in actions])

    def test_end_counts_include_the_history_counts_when_asked(self):
        lines = self.export(import_history="true")
        counts = lines[-1]["counts"]
        self.assertEqual(set(COUNT_KEYS) | {"test_imports", "test_import_actions"}, set(counts))
        self.assertEqual(Test_Import.objects.filter(test__engagement__product_id=2).count(), counts["test_imports"])
        self.assertEqual(sum(line["type"] == "test_import" for line in lines), counts["test_imports"])
        self.assertEqual(
            Test_Import_Finding_Action.objects.filter(test_import__test__engagement__product_id=2).count(), counts["test_import_actions"],
        )
        action_lines = [line["data"]["actions"] for line in lines if line["type"] == "test_import_actions"]
        self.assertEqual(sum(len(actions) for actions in action_lines), counts["test_import_actions"])

    def test_a_product_with_no_imports_has_no_history_lines(self):
        lines = self.export(3, import_history="true")
        self.assertEqual(["header", "end"], [line["type"] for line in lines])
        self.assertEqual({0}, set(lines[-1]["counts"].values()))
        self.assertEqual({"test_imports", "test_import_actions"}, set(lines[-1]["counts"]) - set(COUNT_KEYS))

    def test_the_manifest_counts_match_the_end_line(self):
        url = reverse("export-manifest")
        manifest = self.client.get(url, {"import_history": "true"}).json()
        end = self.end_line(import_history="true")["counts"]
        entry = self.get_results_by_id(manifest["products"], 2)["counts"]
        for key in ("test_imports", "test_import_actions"):
            self.assertEqual(end[key], entry[key], key)
            self.assertEqual(sum(product["counts"][key] for product in manifest["products"]), manifest["totals"][key], key)
            for product_type in manifest["product_types"]:
                members = [product for product in manifest["products"] if product["prod_type"] == product_type["id"]]
                self.assertEqual(sum(product["counts"][key] for product in members), product_type["counts"][key], key)
        plain = self.client.get(url).json()
        self.assertNotIn("test_imports", self.get_results_by_id(plain["products"], 2)["counts"])
        self.assertNotIn("test_imports", plain["totals"])

    def test_a_value_that_is_not_a_boolean_gets_a_400(self):
        for url in (reverse("export-product", args=[2]), reverse("export-manifest")):
            for name in ("import_history", "audit_history"):
                with self.subTest(url=url, name=name):
                    self.assertEqual(400, self.client.get(url, {name: "maybe"}).status_code)


@versioned_fixtures
class TestExportAuditHistory(DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]
    AUDIT_LABELS = ["dojo.product", "dojo.engagement", "dojo.test", "dojo.finding", "dojo.finding_group", "dojo.risk_acceptance"]

    @classmethod
    def setUpTestData(cls):
        cls.admin = Dojo_User.objects.get(username="admin")
        cls.finding = Finding.objects.filter(test__engagement__product_id=2).order_by("id").first()
        cls.other_product_finding = Finding.objects.filter(test__engagement__product_id=1).order_by("id").first()
        cls.group = Finding_Group.objects.create(name="grp", test=cls.finding.test, creator=cls.admin)
        # One acceptance held by an engagement, one that only accepts a finding, one of another product, one of both.
        cls.held = Risk_Acceptance.objects.create(name="held", owner=cls.admin)
        cls.finding.test.engagement.risk_acceptance.add(cls.held)
        cls.accepting = Risk_Acceptance.objects.create(name="accepting", owner=cls.admin)
        cls.accepting.accepted_findings.add(cls.finding)
        cls.foreign = Risk_Acceptance.objects.create(name="foreign", owner=cls.admin)
        cls.foreign.accepted_findings.add(cls.other_product_finding)
        cls.shared = Risk_Acceptance.objects.create(name="shared", owner=cls.admin)
        cls.shared.accepted_findings.add(cls.finding, cls.other_product_finding)
        cls.finding_type = ContentType.objects.get_for_model(Finding)

    def setUp(self):
        super().setUp()
        self.login_as_admin()

    def export(self, product_id=2, **params):
        return ndjson_lines(self.client.get(reverse("export-product", args=[product_id]), params))

    def sent(self, lines, line_type):
        return [line["data"] for line in lines if line["type"] == line_type]

    def legacy_entry(self, obj, **fields):
        return LogEntry.objects.create(
            content_type=ContentType.objects.get_for_model(type(obj)),
            object_pk=str(obj.pk),
            object_id=obj.pk,
            object_repr="obj",
            action=1,
            changes={"title": ["A", "B"]},
            **fields,
        )

    def legacy_entry_for_every_model(self):
        test = self.finding.test
        for obj in (test.engagement.product, test.engagement, test, self.finding, self.group, self.shared, self.foreign):
            self.legacy_entry(obj)

    def objects_of(self, product_id):
        acceptances = Q(engagement__product_id=product_id) | Q(accepted_findings__test__engagement__product_id=product_id)
        return {
            Product: {product_id},
            Engagement: set(Engagement.objects.filter(product_id=product_id).values_list("id", flat=True)),
            Test: set(Test.objects.filter(engagement__product_id=product_id).values_list("id", flat=True)),
            Finding: set(Finding.objects.filter(test__engagement__product_id=product_id).values_list("id", flat=True)),
            Finding_Group: set(Finding_Group.objects.filter(test__engagement__product_id=product_id).values_list("id", flat=True)),
            Risk_Acceptance: set(Risk_Acceptance.objects.filter(acceptances).values_list("id", flat=True)),
        }

    def expected_counts(self, product_id):
        events = entries = 0
        for model, ids in self.objects_of(product_id).items():
            events += apps.get_model("dojo", f"{model.__name__}Event").objects.filter(pgh_obj_id__in=ids).count()
            entries += LogEntry.objects.filter(content_type=ContentType.objects.get_for_model(model), object_id__in=ids).count()
        return {"audit_events": events, "legacy_audit_entries": entries}

    def test_the_stream_has_no_audit_lines_by_default(self):
        self.legacy_entry(self.finding)
        for params in ({}, {"audit_history": "false"}):
            lines = self.export(**params)
            self.assertEqual({"header", "engagement", "test", "finding", "risk_acceptance", "end"}, {line["type"] for line in lines})
            self.assertEqual(set(COUNT_KEYS), set(lines[-1]["counts"]))

    def test_audit_history_alone_adds_the_audit_lines_and_their_counts(self):
        self.legacy_entry(self.finding)
        lines = self.export(audit_history="true")
        self.assertEqual({"audit_event", "legacy_audit_entry"}, {line["type"] for line in lines} - {"header", "engagement", "test", "finding", "risk_acceptance", "end"})
        self.assertEqual(set(COUNT_KEYS) | {"audit_events", "legacy_audit_entries"}, set(lines[-1]["counts"]))

    def test_the_audit_lines_come_after_the_import_history_and_before_the_end_line(self):
        self.legacy_entry(self.finding)
        rank = {"risk_acceptance": 0, "test_import": 1, "test_import_actions": 1, "audit_event": 2, "legacy_audit_entry": 3, "end": 4}
        kinds = [line["type"] for line in self.export(import_history="true", audit_history="true") if line["type"] in rank]
        self.assertEqual(sorted(kinds, key=rank.__getitem__), kinds)
        self.assertEqual({0, 1, 2, 3, 4}, {rank[kind] for kind in kinds})

    def test_audit_events_are_the_product_s_objects_events_with_their_context(self):
        with pghistory.context(user=self.admin.id, url="/finding/1", remote_addr="192.0.2.10"):
            self.finding.title = "Edited"
            self.finding.save()
        events = self.sent(self.export(audit_history="true"), "audit_event")
        edit = next(e for e in events if e["model"] == "dojo.finding" and e["pgh_label"] == "update")
        self.assertEqual("Edited", edit["data"]["title"])
        self.assertEqual("/finding/1", edit["context"]["metadata"]["url"])
        self.assertNotIn(self.other_product_finding.id, {e["pgh_obj_id"] for e in events if e["model"] == "dojo.finding"})

    def test_an_event_carries_the_source_values_and_dates(self):
        with pghistory.context(user=self.admin.id):
            self.finding.title = "Edited"
            self.finding.save()
        events = self.sent(self.export(audit_history="true"), "audit_event")
        edit = next(e for e in events if e["model"] == "dojo.finding" and e["pgh_label"] == "update" and e["pgh_obj_id"] == self.finding.id)
        row = FindingEvent.objects.select_related("pgh_context").get(pgh_id=edit["pgh_id"])
        self.assertEqual({"model", "pgh_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "data", "context"}, set(edit))
        self.assertEqual(render_datetime(row.pgh_created_at), edit["pgh_created_at"])
        self.assertEqual(row.pgh_created_at, datetime.fromisoformat(edit["pgh_created_at"]))
        self.assertEqual(
            {field.attname for field in FindingEvent._meta.concrete_fields if not field.name.startswith("pgh_")}, set(edit["data"]),
        )
        self.assertEqual((self.finding.id, self.finding.test_id), (edit["data"]["id"], edit["data"]["test_id"]))
        for field in FindingEvent._meta.concrete_fields:
            value = getattr(row, field.attname)
            if isinstance(value, datetime) and not field.name.startswith("pgh_"):
                self.assertEqual(render_datetime(value), edit["data"][field.attname], field.attname)
        self.assertEqual(
            {"id": str(row.pgh_context_id), "created_at": render_datetime(row.pgh_context.created_at),
             "updated_at": render_datetime(row.pgh_context.updated_at), "metadata": row.pgh_context.metadata},
            edit["context"],
        )
        self.assertEqual(self.admin.id, edit["context"]["metadata"]["user"])

    def test_an_event_with_no_context_has_a_null_context(self):
        events = self.sent(self.export(audit_history="true"), "audit_event")
        row = FindingEvent.objects.filter(pgh_context__isnull=True, pgh_obj_id=self.finding.id).order_by("pgh_id").first()
        self.assertIsNotNone(row)
        sent = next(e for e in events if e["model"] == "dojo.finding" and e["pgh_id"] == row.pgh_id)
        self.assertIsNone(sent["context"])

    def test_a_risk_acceptance_event_sends_the_file_name(self):
        proof = Risk_Acceptance.objects.create(name="proof", owner=self.admin, path=ContentFile(b"proof", name="waiver.txt"))
        self.addCleanup(proof.path.storage.delete, proof.path.name)
        proof.accepted_findings.add(self.finding)
        events = self.sent(self.export(audit_history="true"), "audit_event")
        sent = [e for e in events if e["model"] == "dojo.risk_acceptance" and e["pgh_obj_id"] == proof.id]
        self.assertTrue(sent)
        self.assertEqual({proof.path.name}, {e["data"]["path"] for e in sent})

    def test_events_come_in_model_order_then_pgh_id_and_cover_the_six_models(self):
        events = self.sent(self.export(audit_history="true"), "audit_event")
        labels = [e["model"] for e in events]
        self.assertEqual(sorted(labels, key=self.AUDIT_LABELS.index), labels)
        for model, ids in self.objects_of(2).items():
            label = model._meta.label_lower
            mine = [e for e in events if e["model"] == label]
            self.assertEqual(sorted(e["pgh_id"] for e in mine), [e["pgh_id"] for e in mine], label)
            self.assertEqual(ids, {e["pgh_obj_id"] for e in mine}, label)
        self.assertEqual(set(self.AUDIT_LABELS), set(labels))

    def test_risk_acceptance_events_follow_either_link_and_skip_other_products(self):
        ids = {
            product_id: {
                e["pgh_obj_id"]
                for e in self.sent(self.export(product_id, audit_history="true"), "audit_event")
                if e["model"] == "dojo.risk_acceptance"
            }
            for product_id in (1, 2)
        }
        self.assertLessEqual({self.held.id, self.accepting.id, self.shared.id}, ids[2])
        self.assertNotIn(self.foreign.id, ids[2])
        self.assertLessEqual({self.foreign.id, self.shared.id}, ids[1])
        self.assertFalse({self.held.id, self.accepting.id} & ids[1])

    def test_a_deleted_object_s_events_are_not_sent(self):
        doomed = Finding.objects.create(title="doomed", test=self.finding.test, reporter=self.admin, severity="Low")
        self.legacy_entry(doomed)
        doomed_id = doomed.id
        doomed.delete()
        self.assertTrue(FindingEvent.objects.filter(pgh_obj_id=doomed_id, pgh_label="delete").exists())
        lines = self.export(audit_history="true")
        sent = {e["pgh_obj_id"] for e in self.sent(lines, "audit_event") if e["model"] == "dojo.finding"}
        self.assertIn(self.finding.id, sent)
        self.assertNotIn(doomed_id, sent)
        self.assertNotIn(doomed_id, {e["object_id"] for e in self.sent(lines, "legacy_audit_entry")})

    def test_legacy_entries_of_the_product_s_objects_are_sent(self):
        LogEntry.objects.create(
            content_type=self.finding_type, object_pk=str(self.finding.id), object_id=self.finding.id, object_repr="F", action=1,
            changes={"title": ["A", "B"]},
        )
        entries = self.sent(self.export(audit_history="true"), "legacy_audit_entry")
        sent = next(e for e in entries if e["content_type"] == "dojo.finding" and e["object_id"] == self.finding.id)
        self.assertEqual({"title": ["A", "B"]}, sent["changes"])

    def test_a_legacy_entry_carries_every_field_by_attname(self):
        stamp = datetime(2020, 1, 2, 3, 4, 5, 678901, tzinfo=UTC)
        entry = self.legacy_entry(
            self.finding, actor=self.admin, remote_addr="192.0.2.10", remote_port=443, cid="c1", actor_email="a@example.com",
            additional_data={"k": "v"}, serialized_data={"s": 1},
        )
        LogEntry.objects.filter(id=entry.id).update(timestamp=stamp)
        entry.refresh_from_db()
        sent = next(e for e in self.sent(self.export(audit_history="true"), "legacy_audit_entry") if e["id"] == entry.id)
        concrete = {field.attname for field in LogEntry._meta.concrete_fields}
        self.assertEqual((concrete - {"content_type_id"}) | {"content_type"}, set(sent))
        self.assertEqual("2020-01-02T03:04:05.678901Z", sent["timestamp"])
        self.assertEqual(
            (self.admin.id, "192.0.2.10", 443, "c1", "a@example.com", {"k": "v"}, {"s": 1}, 1, str(self.finding.id), "obj"),
            (sent["actor_id"], sent["remote_addr"], sent["remote_port"], sent["cid"], sent["actor_email"], sent["additional_data"],
             sent["serialized_data"], sent["action"], sent["object_pk"], sent["object_repr"]),
        )

    def test_legacy_entries_are_limited_to_the_product_s_audited_models_and_objects(self):
        mine = [self.legacy_entry(self.finding), self.legacy_entry(self.finding.test), self.legacy_entry(self.held)]
        foreign = [self.legacy_entry(self.other_product_finding), self.legacy_entry(self.foreign)]
        not_audited = [self.legacy_entry(Notes.objects.create(entry="n", author=self.admin))]
        mine.append(self.legacy_entry(self.finding))
        ids = [e["id"] for e in self.sent(self.export(audit_history="true"), "legacy_audit_entry")]
        self.assertEqual(sorted(ids), ids)
        self.assertLessEqual({e.id for e in mine}, set(ids))
        self.assertFalse({e.id for e in foreign + not_audited} & set(ids))

    def test_each_model_reads_its_legacy_entries_in_its_own_query(self):
        with CaptureQueriesContext(connection) as queries:
            self.export(audit_history="true")
        legacy = [query["sql"] for query in queries if 'FROM "auditlog_logentry"' in query["sql"]]
        self.assertEqual(len(AUDIT_MODELS), len(legacy), legacy)
        for sql in legacy:
            self.assertEqual(1, len(re.findall(r'"auditlog_logentry"\."content_type_id" = (?!"django_content_type")', sql)), sql)

    def test_the_end_counts_match_the_lines_and_the_database(self):
        self.legacy_entry_for_every_model()
        for product_id in (1, 2, 3):
            lines = self.export(product_id, audit_history="true")
            counts = lines[-1]["counts"]
            self.assertEqual(len(self.sent(lines, "audit_event")), counts["audit_events"])
            self.assertEqual(len(self.sent(lines, "legacy_audit_entry")), counts["legacy_audit_entries"])
            expected = self.expected_counts(product_id)
            self.assertEqual(expected, {key: counts[key] for key in expected}, product_id)

    def test_the_manifest_counts_appear_only_when_asked_and_match_the_end_line(self):
        self.legacy_entry_for_every_model()
        url = reverse("export-manifest")
        plain = self.client.get(url).json()
        self.assertNotIn("audit_events", plain["totals"])
        self.assertNotIn("legacy_audit_entries", plain["totals"])
        manifest = self.client.get(url, {"audit_history": "true"}).json()
        keys = ("audit_events", "legacy_audit_entries")
        for entry in manifest["products"]:
            self.assertEqual(set(COUNT_KEYS) | set(keys), set(entry["counts"]))
            end = self.export(entry["id"], audit_history="true")[-1]["counts"]
            for key in keys:
                self.assertEqual(end[key], entry["counts"][key], (entry["id"], key))
        self.assertNotIn("test_imports", manifest["totals"])
        for key in keys:
            self.assertGreater(manifest["totals"][key], 0, key)
            self.assertEqual(sum(entry["counts"][key] for entry in manifest["products"]), manifest["totals"][key], key)
            for product_type in manifest["product_types"]:
                members = [entry for entry in manifest["products"] if entry["prod_type"] == product_type["id"]]
                self.assertEqual(sum(entry["counts"][key] for entry in members), product_type["counts"][key], key)
        self.assertNotIn("audit_events", self.get_results_by_id(plain["products"], 2)["counts"])

    def test_the_manifest_counts_ignore_the_history_of_deleted_objects(self):
        def counts():
            manifest = self.client.get(reverse("export-manifest"), {"audit_history": "true"}).json()
            return {key: self.get_results_by_id(manifest["products"], 2)["counts"][key] for key in ("audit_events", "legacy_audit_entries")}

        baseline = counts()
        doomed = Finding.objects.create(title="doomed", test=self.finding.test, reporter=self.admin, severity="Low")
        self.legacy_entry(doomed)
        grown = counts()
        self.assertGreater(grown["audit_events"], baseline["audit_events"])
        self.assertGreater(grown["legacy_audit_entries"], baseline["legacy_audit_entries"])
        doomed.delete()
        self.assertEqual(baseline, counts())


@versioned_fixtures
class TestExportManifest(DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        seed_product(cls)
        UserContactInfo.objects.get_or_create(user=Dojo_User.objects.get(username="user1"))
        Product.objects.get(id=2).tags.add("alpha", "beta")
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
                "product_types", "products", "totals", "announcement", "login_banner", "features", "deduplication",
            },
            set(self.manifest),
        )
        self.assertEqual(1, self.manifest["schema"])
        self.assertEqual(str(System_Settings.objects.get(no_cache=True).install_id), self.manifest["source"]["install_id"])
        for entry in self.manifest["products"]:
            self.assertEqual(set(COUNT_KEYS), set(entry["counts"]))

    def test_product_entries_carry_the_record_fields(self):
        entry = self.get_results_by_id(self.manifest["products"], 2)
        product = Product.objects.get(id=2)
        self.assertEqual(
            {"id", "name", "prod_type", "counts", "description", "tags", "business_criticality",
             "sla_configuration", "product_manager", "technical_contact", "team_manager"},
            set(entry),
        )
        self.assertEqual(product.description, entry["description"])
        self.assertEqual(["alpha", "beta"], sorted(entry["tags"]))
        self.assertEqual(sorted(str(tag) for tag in product.tags.all()), sorted(entry["tags"]))
        self.assertEqual(product.sla_configuration_id, entry["sla_configuration"])
        self.assertEqual(product.business_criticality, entry["business_criticality"])
        self.assertEqual(
            (product.product_manager_id, product.technical_contact_id, product.team_manager_id),
            (entry["product_manager"], entry["technical_contact"], entry["team_manager"]),
        )

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
        unlinked = Risk_Acceptance.objects.create(name="unlinked", owner=self.admin)
        unlinked.accepted_findings.add(second)
        unlinked.notes.add(note)
        cross = Risk_Acceptance.objects.create(name="cross", owner=self.admin)
        cross.accepted_findings.add(Finding.objects.filter(test__engagement__product_id=1).order_by("id").first())
        first.test.engagement.risk_acceptance.add(cross)
        for product_id in (1, 2):
            for params in ({}, {"max_file_bytes": 4}):
                with self.subTest(product_id=product_id, params=params):
                    counts = self.get_results_by_id(self.client.get(self.url, params).json()["products"], product_id)["counts"]
                    end = ndjson_lines(self.client.get(reverse("export-product", args=[product_id]), params))[-1]["counts"]
                    for key in ("engagements", "tests", "findings", "notes", "files", "files_over_cap", "risk_acceptances"):
                        self.assertEqual(end[key], counts[key], key)
                    # Every seeded file holds 5 bytes, so all are over a cap of 4 and none are over the default.
                    self.assertEqual(counts["files"] if params else 0, counts["files_over_cap"])
                    self.assertEqual(1 if product_id == 2 else 0, counts["finding_groups"])

    def manifest_with_stat_calls(self, params):
        storage = FileUpload._meta.get_field("file").storage
        with (
            mock.patch.object(storage, "size", wraps=storage.size) as size,
            mock.patch.object(storage, "exists", wraps=storage.exists) as exists,
        ):
            manifest = self.client.get(self.url, params).json()
        return manifest, size.call_count, exists.call_count

    def test_file_counts_true_is_the_default_and_stats_each_file_once(self):
        files = {
            file_id
            for through in (Engagement.files.through, Test.files.through, Finding.files.through)
            for file_id in through.objects.values_list("fileupload_id", flat=True)
        }
        for params in ({}, {"file_counts": "true"}):
            with self.subTest(params=params):
                manifest, sizes, exists = self.manifest_with_stat_calls(params)
                self.assertEqual(self.manifest["products"], manifest["products"])
                self.assertEqual(self.manifest["totals"], manifest["totals"])
                self.assertEqual((len(files), 0), (sizes, exists))
        self.assertEqual(3, self.get_results_by_id(self.manifest["products"], 2)["counts"]["files"])

    def test_a_file_name_the_server_cannot_encode_does_not_fail_the_manifest(self):
        storage = FileUpload._meta.get_field("file").storage
        refused = UnicodeEncodeError("ascii", "\u00fc", 0, 1, "ordinal not in range(128)")
        with mock.patch.object(storage, "size", side_effect=refused):
            response = self.client.get(self.url, {"max_file_bytes": 4})
        self.assertEqual(200, response.status_code)
        self.assertEqual(0, response.json()["totals"]["files_over_cap"])

    def test_file_counts_false_skips_the_file_stat(self):
        manifest, sizes, exists = self.manifest_with_stat_calls({"file_counts": "false", "max_file_bytes": 4})
        self.assertEqual((0, 0), (sizes, exists))
        all_counts = [
            *(entry["counts"] for entry in manifest["products"]),
            *(entry["counts"] for entry in manifest["product_types"]),
            manifest["totals"],
        ]
        for counts in all_counts:
            self.assertIsNone(counts["files_over_cap"])
        for key in ("files", "findings", "notes"):
            self.assertEqual(self.manifest["totals"][key], manifest["totals"][key], key)
        self.assertEqual(3, self.get_results_by_id(manifest["products"], 2)["counts"]["files"])
        self.assertEqual(4, manifest["max_file_bytes"])

    def test_file_counts_must_be_a_boolean(self):
        response = self.client.get(self.url, {"file_counts": "maybe"})
        self.assertEqual(400, response.status_code, response.content[:1000])
        self.assertIn("file_counts", response.json())

    def test_the_stream_ignores_file_counts(self):
        response = self.client.get(reverse("export-product", args=[2]), {"file_counts": "false"})
        self.assertEqual(3, ndjson_lines(response)[-1]["counts"]["files"])

    def test_empty_file_counts_uses_the_default(self):
        response = self.client.get(self.url, {"file_counts": "", "max_file_bytes": 4})
        self.assertEqual(200, response.status_code)
        counts = self.get_results_by_id(response.json()["products"], 2)["counts"]
        self.assertEqual((3, 3), (counts["files"], counts["files_over_cap"]))

    def test_a_missing_file_is_counted_but_not_over_cap(self):
        file_upload = make_file(self, "gone.txt")
        self.finding.files.add(file_upload)
        file_upload.file.storage.delete(file_upload.file.name)
        counts = self.get_results_by_id(self.client.get(self.url, {"max_file_bytes": 4}).json()["products"], 2)["counts"]
        self.assertEqual((4, 3), (counts["files"], counts["files_over_cap"]))

    def test_manifest_counts_a_risk_acceptance_linked_only_through_a_finding(self):
        # Regression: the manifest counted acceptances through their engagement link only.
        before = self.get_results_by_id(self.manifest["products"], 2)["counts"]
        unlinked = Risk_Acceptance.objects.create(name="unlinked", owner=self.admin)
        unlinked.accepted_findings.add(self.finding)
        unlinked.notes.add(Notes.objects.create(entry="unlinked note", author=self.admin))
        counts = self.get_results_by_id(self.client.get(self.url).json()["products"], 2)["counts"]
        self.assertEqual(before["risk_acceptances"] + 1, counts["risk_acceptances"])
        self.assertEqual(before["notes"] + 1, counts["notes"])

    def test_reference_data(self):
        reference = self.manifest["reference"]
        self.assertEqual(
            {
                "sla_configurations", "development_environments", "regulations", "test_types", "note_types",
                "product_platforms", "product_lifecycles", "product_origins", "finding_templates", "tool_types",
                "tool_configurations", "users", "contacts", "report_types",
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

    def test_reference_test_types_carry_dynamically_generated(self):
        created = Test_Type.objects.create(name="Acme Scan (SARIF)", dynamically_generated=True, static_tool=True)
        rows = self.client.get(self.url).json()["reference"]["test_types"]
        row = next(row for row in rows if row["name"] == "Acme Scan (SARIF)")
        self.assertEqual(
            {
                "id": created.id, "name": "Acme Scan (SARIF)", "static_tool": True, "dynamic_tool": False,
                "active": True, "dynamically_generated": True,
            },
            row,
        )

    def test_reference_carries_finding_templates_tool_types_and_tool_configurations(self):
        reference = self.manifest["reference"]
        for key, model in (
            ("finding_templates", Finding_Template),
            ("tool_types", Tool_Type),
            ("tool_configurations", Tool_Configuration),
        ):
            ids = [entry["id"] for entry in reference[key]]
            self.assertTrue(ids, key)
            self.assertEqual(list(model.objects.order_by("id").values_list("id", flat=True)), ids, key)
        template = self.get_results_by_id(reference["finding_templates"], 1)
        self.assertEqual(Finding_Template.objects.get(id=1).title, template["title"])
        self.assertEqual(Finding_Template.objects.get(id=1).severity, template["severity"])
        tool_type = self.get_results_by_id(reference["tool_types"], 1)
        self.assertEqual("Tool Type 1", tool_type["name"])
        configuration = self.get_results_by_id(reference["tool_configurations"], 1)
        self.assertEqual(
            (1, "Tool Configuration 1", "http://www.example.com", "Password", "user1"),
            (
                configuration["tool_type"], configuration["name"], configuration["url"],
                configuration["authentication_type"], configuration["username"],
            ),
        )

    def test_tool_configurations_carry_no_secret(self):
        secrets = {
            "password": "hunter2", "ssh": "PRIVATE-KEY-MATERIAL", "api_key": "TOKEN-VALUE", "extras": "ORG-TOKEN",
        }
        Tool_Configuration.objects.filter(id=1).update(**secrets)
        manifest = self.client.get(self.url).json()
        self.assertTrue(manifest["reference"]["tool_configurations"])
        for entry in manifest["reference"]["tool_configurations"]:
            for field in secrets:
                self.assertNotIn(field, entry)
        body = json.dumps(manifest)
        for value in secrets.values():
            self.assertNotIn(value, body)

    def test_features_list_check_lists_and_the_history_parts(self):
        self.assertEqual(["check_lists", "import_history", "audit_history"], self.manifest["features"])

    def test_the_manifest_counts_import_history_only_when_asked(self):
        self.assertNotIn("test_imports", self.manifest["totals"])
        self.assertNotIn("test_import_actions", self.manifest["totals"])
        totals = self.client.get(self.url, {"import_history": "true"}).json()["totals"]
        self.assertEqual(2, totals["test_imports"])
        self.assertEqual(Test_Import_Finding_Action.objects.count(), totals["test_import_actions"])

    def test_announcement_is_the_single_row(self):
        row = Announcement.objects.get()
        self.assertEqual(
            {"message": row.message, "style": row.style, "dismissable": row.dismissable},
            self.client.get(self.url).json()["announcement"],
        )

    def test_announcement_is_null_without_a_row(self):
        Announcement.objects.all().delete()
        self.assertIsNone(self.client.get(self.url).json()["announcement"])

    def test_login_banner_is_the_banner_row(self):
        BannerConf.objects.all().delete()
        BannerConf.objects.create(banner_enable=True, banner_message="Welcome <b>back</b>")
        self.assertEqual(
            {"banner_enable": True, "banner_message": "Welcome <b>back</b>"},
            self.client.get(self.url).json()["login_banner"],
        )

    def test_login_banner_is_null_without_a_row(self):
        BannerConf.objects.all().delete()
        self.assertIsNone(self.client.get(self.url).json()["login_banner"])

    def test_contacts_list_every_row_by_id(self):
        pat = Contact.objects.create(name="Pat Doe", email="pat@example.com", team="Red", is_admin=True)
        sam = Contact.objects.create(name="Sam Roe", email="sam@example.com", team="Blue", is_globally_read_only=True)
        contacts = self.client.get(self.url).json()["reference"]["contacts"]
        self.assertEqual(
            [
                {
                    "id": contact.id, "name": contact.name, "email": contact.email, "team": contact.team,
                    "is_admin": contact.is_admin, "is_globally_read_only": contact.is_globally_read_only,
                }
                for contact in Contact.objects.order_by("id")
            ],
            contacts,
        )
        by_id = {contact["id"]: contact for contact in contacts}
        self.assertEqual((True, False), (by_id[pat.id]["is_admin"], by_id[pat.id]["is_globally_read_only"]))
        self.assertEqual((False, True), (by_id[sam.id]["is_admin"], by_id[sam.id]["is_globally_read_only"]))

    def test_report_types_list_every_row_by_id(self):
        report_types = self.manifest["reference"]["report_types"]
        self.assertTrue(report_types)
        self.assertEqual(
            [{"id": row.id, "name": row.name} for row in Report_Type.objects.order_by("id")], report_types,
        )

    def test_new_keys_carry_no_archive_fields(self):
        BannerConf.objects.all().delete()
        BannerConf.objects.create(banner_enable=False, banner_message="x")
        Contact.objects.create(name="Pat Doe", email="pat@example.com", team="Red")
        manifest = self.client.get(self.url).json()
        rows = [
            manifest["announcement"], manifest["login_banner"],
            *manifest["reference"]["contacts"], *manifest["reference"]["report_types"],
        ]
        self.assertNotIn(None, rows)
        for row in rows:
            self.assertEqual(set(), {"archived_at", "archive_batch"} & set(row))

    def deduplication(self, **overrides):
        with override_settings(**overrides):
            return self.client.get(self.url).json()["deduplication"]

    def test_deduplication_is_three_empty_maps_when_nothing_differs(self):
        empty = {"algorithm_per_parser": {}, "hashcode_fields_per_scanner": {}, "hashcode_allows_null_cwe": {}}
        self.assertEqual(empty, self.manifest["deduplication"])

    def test_deduplication_lists_a_changed_field_list_only(self):
        fields = {**settings.HASHCODE_FIELDS_PER_SCANNER_SHIPPED, "Anchore Engine Scan": ["title", "cwe"]}
        self.assertEqual(
            {
                "algorithm_per_parser": {},
                "hashcode_fields_per_scanner": {"Anchore Engine Scan": ["title", "cwe"]},
                "hashcode_allows_null_cwe": {},
            },
            self.deduplication(HASHCODE_FIELDS_PER_SCANNER=fields),
        )

    def test_deduplication_treats_a_tuple_and_a_list_with_the_same_fields_as_equal(self):
        shipped = settings.HASHCODE_FIELDS_PER_SCANNER_SHIPPED
        fields = {**shipped, "Anchore Engine Scan": tuple(shipped["Anchore Engine Scan"])}
        self.assertEqual({}, self.deduplication(HASHCODE_FIELDS_PER_SCANNER=fields)["hashcode_fields_per_scanner"])

    def test_deduplication_sends_a_changed_tuple_as_a_list(self):
        fields = {**settings.HASHCODE_FIELDS_PER_SCANNER_SHIPPED, "Anchore Engine Scan": ("title", "cwe")}
        self.assertEqual(
            {"Anchore Engine Scan": ["title", "cwe"]},
            self.deduplication(HASHCODE_FIELDS_PER_SCANNER=fields)["hashcode_fields_per_scanner"],
        )

    def test_deduplication_lists_a_changed_algorithm_only(self):
        algorithms = {**settings.DEDUPLICATION_ALGORITHM_PER_PARSER_SHIPPED, "Anchore Engine Scan": "unique_id_from_tool"}
        self.assertEqual(
            {
                "algorithm_per_parser": {"Anchore Engine Scan": "unique_id_from_tool"},
                "hashcode_fields_per_scanner": {},
                "hashcode_allows_null_cwe": {},
            },
            self.deduplication(DEDUPLICATION_ALGORITHM_PER_PARSER=algorithms),
        )

    def test_deduplication_lists_a_changed_null_cwe_value_only(self):
        null_cwe = {**settings.HASHCODE_ALLOWS_NULL_CWE_SHIPPED, "Anchore Engine Scan": False}
        self.assertEqual(
            {
                "algorithm_per_parser": {},
                "hashcode_fields_per_scanner": {},
                "hashcode_allows_null_cwe": {"Anchore Engine Scan": False},
            },
            self.deduplication(HASHCODE_ALLOWS_NULL_CWE=null_cwe),
        )

    def test_deduplication_lists_a_scan_type_the_shipped_maps_lack(self):
        self.assertEqual(
            {
                "algorithm_per_parser": {"Acme Scan": "hash_code"},
                "hashcode_fields_per_scanner": {"Acme Scan": ["title", "file_path"]},
                "hashcode_allows_null_cwe": {"Acme Scan": True},
            },
            self.deduplication(
                DEDUPLICATION_ALGORITHM_PER_PARSER={**settings.DEDUPLICATION_ALGORITHM_PER_PARSER_SHIPPED, "Acme Scan": "hash_code"},
                HASHCODE_FIELDS_PER_SCANNER={**settings.HASHCODE_FIELDS_PER_SCANNER_SHIPPED, "Acme Scan": ["title", "file_path"]},
                HASHCODE_ALLOWS_NULL_CWE={**settings.HASHCODE_ALLOWS_NULL_CWE_SHIPPED, "Acme Scan": True},
            ),
        )

    def test_deduplication_sends_a_removed_algorithm_as_legacy(self):
        algorithms = {key: value for key, value in settings.DEDUPLICATION_ALGORITHM_PER_PARSER_SHIPPED.items() if key != "Anchore Engine Scan"}
        self.assertEqual(
            {
                "algorithm_per_parser": {"Anchore Engine Scan": "legacy"},
                "hashcode_fields_per_scanner": {},
                "hashcode_allows_null_cwe": {},
            },
            self.deduplication(DEDUPLICATION_ALGORITHM_PER_PARSER=algorithms),
        )

    def test_deduplication_sends_a_removed_field_list_as_an_empty_list(self):
        fields = {key: value for key, value in settings.HASHCODE_FIELDS_PER_SCANNER_SHIPPED.items() if key != "Anchore Engine Scan"}
        self.assertEqual(
            {
                "algorithm_per_parser": {},
                "hashcode_fields_per_scanner": {"Anchore Engine Scan": []},
                "hashcode_allows_null_cwe": {},
            },
            self.deduplication(HASHCODE_FIELDS_PER_SCANNER=fields),
        )

    def test_deduplication_sends_a_removed_null_cwe_value_as_true(self):
        null_cwe = {key: value for key, value in settings.HASHCODE_ALLOWS_NULL_CWE_SHIPPED.items() if key != "Checkmarx Scan"}
        self.assertFalse(settings.HASHCODE_ALLOWS_NULL_CWE_SHIPPED["Checkmarx Scan"])
        self.assertEqual(
            {
                "algorithm_per_parser": {},
                "hashcode_fields_per_scanner": {},
                "hashcode_allows_null_cwe": {"Checkmarx Scan": True},
            },
            self.deduplication(HASHCODE_ALLOWS_NULL_CWE=null_cwe),
        )

    def test_deduplication_skips_a_removed_scan_type_whose_fallback_is_its_shipped_value(self):
        null_cwe = {key: value for key, value in settings.HASHCODE_ALLOWS_NULL_CWE_SHIPPED.items() if key != "Anchore Engine Scan"}
        self.assertTrue(settings.HASHCODE_ALLOWS_NULL_CWE_SHIPPED["Anchore Engine Scan"])
        self.assertEqual({}, self.deduplication(HASHCODE_ALLOWS_NULL_CWE=null_cwe)["hashcode_allows_null_cwe"])

    def test_the_fallback_values_are_what_a_test_uses_without_the_scan_type(self):
        test = Test(scan_type="Checkmarx Scan", test_type=Test_Type(name="Checkmarx Scan"))
        with override_settings(
            DEDUPLICATION_ALGORITHM_PER_PARSER={},
            HASHCODE_FIELDS_PER_SCANNER={},
            HASHCODE_ALLOWS_NULL_CWE={},
        ):
            rules = self.client.get(self.url).json()["deduplication"]
            self.assertEqual(rules["algorithm_per_parser"]["Checkmarx Scan"], test.deduplication_algorithm)
            self.assertFalse(test.hash_code_fields)
            self.assertEqual([], rules["hashcode_fields_per_scanner"]["Checkmarx Scan"])
            self.assertEqual(rules["hashcode_allows_null_cwe"]["Checkmarx Scan"], test.hash_code_allows_null_cwe)

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
