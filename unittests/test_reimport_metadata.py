import json

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client
from django.urls import reverse
from django.utils import timezone
from parameterized import parameterized

from dojo.importers.default_reimporter import DefaultReImporter
from dojo.models import Engagement, Test, Test_Type

from .dojo_test_case import DojoAPITestCase, DojoTestCase, versioned_fixtures

METADATA = {
    "version": "1.2.3",
    "branch_tag": "main",
    "build_id": "build-42",
    "commit_hash": "deadbeef",
}
REPLACEMENTS = {
    "version": "2.0.0",
    "branch_tag": "release",
    "build_id": "build-43",
    "commit_hash": "cafebabe",
}


class ReimportMetadataMixin:
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.login_as_admin()
        user = self.get_test_admin()
        user.usercontactinfo.block_execution = True
        user.usercontactinfo.save()
        self.client_ui = Client()
        self.client_ui.force_login(user)

    def scan_payload(self):
        scan = {"findings": [{"title": "Metadata regression", "severity": "High", "description": "Test metadata"}]}
        return {
            "scan_type": "Generic Findings Import",
            "minimum_severity": "Info",
            "file": SimpleUploadedFile("scan.json", json.dumps(scan).encode()),
        }

    def assert_metadata(self, test, expected):
        test.refresh_from_db()
        self.assertEqual({field: getattr(test, field) for field in METADATA}, expected)

    def test_initial_import_stores_metadata(self):
        test = self.post_scan(metadata=METADATA)
        self.assert_metadata(test, METADATA)

    @parameterized.expand([
        ("omitted", {}, {}),
        ("empty", dict.fromkeys(METADATA, ""), {}),
        *[(field, {field: value}, {field: value}) for field, value in REPLACEMENTS.items()],
        ("mixed", {"version": "2.0.0", "build_id": "build-43"}, {"version": "2.0.0", "build_id": "build-43"}),
        ("all", REPLACEMENTS, REPLACEMENTS),
    ])
    def test_reimport_metadata(self, name, supplied, updates):
        test = self.post_scan(metadata=METADATA)
        self.post_scan(test=test, metadata=supplied)
        self.assert_metadata(test, METADATA | updates)
        self.assertEqual(test.finding_set.count(), 1)


@versioned_fixtures
class ReimportMetadataAPITest(ReimportMetadataMixin, DojoAPITestCase):
    def post_scan(self, *, metadata, test=None):
        payload = self.scan_payload() | metadata
        if test is None:
            result = self.import_scan(payload | {"engagement": 1}, 201)
        else:
            result = self.reimport_scan(payload | {"test": test.id}, 201)
        return Test.objects.get(id=result["test"])

    @parameterized.expand(list(METADATA))
    def test_whitespace_metadata_is_rejected(self, field):
        test = self.post_scan(metadata=METADATA)
        payload = self.scan_payload() | {"test": test.id, field: " \t "}
        response = self.client.post(reverse("reimportscan-list"), payload)
        self.assertEqual(response.status_code, 400)
        self.assertIn(field, response.data)
        self.assert_metadata(test, METADATA)

    @parameterized.expand([("parser_version", {}, "3.1.4"), ("explicit_version", {"version": "2.0.0"}, "2.0.0")])
    def test_initial_sarif_import_version(self, name, metadata, expected):
        scan = {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Metadata scanner", "version": "3.1.4"}}, "results": []}],
        }
        payload = {
            "engagement": 1,
            "scan_type": "SARIF",
            "file": SimpleUploadedFile("scan.sarif", json.dumps(scan).encode()),
        }
        result = self.import_scan(payload | metadata, 201)
        self.assertEqual(Test.objects.get(id=result["test"]).version, expected)


@versioned_fixtures
class ReimportMetadataUITest(ReimportMetadataMixin, DojoAPITestCase):
    def post_scan(self, *, metadata, test=None):
        payload = self.scan_payload() | metadata | {"active": "not_specified", "verified": "not_specified"}
        if test is None:
            url = reverse("import_scan_results", args=(1,))
            payload["environment"] = 1
        else:
            url = reverse("re_import_scan_results", args=(test.id,))
        response = self.client_ui.post(url, payload)
        self.assertEqual(response.status_code, 302, response.content[:1000])
        result = Test.objects.get(id=response.url.rstrip("/").split("/")[-1])
        self.assertRedirects(response, reverse("view_test", args=(result.id,)), fetch_redirect_response=False)
        return result

    def test_whitespace_metadata_preserves_existing_values(self):
        test = self.post_scan(metadata=METADATA)
        self.post_scan(test=test, metadata=dict.fromkeys(METADATA, " \t "))
        self.assert_metadata(test, METADATA)


@versioned_fixtures
class ReimportMetadataImporterTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        test_type, _ = Test_Type.objects.get_or_create(name="ZAP Scan")
        self.test = Test.objects.create(
            engagement=Engagement.objects.get(id=1),
            test_type=test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
            **METADATA,
        )

    @parameterized.expand([
        ("omitted", {}),
        ("none", dict.fromkeys(METADATA)),
        ("empty", dict.fromkeys(METADATA, "")),
        ("whitespace", dict.fromkeys(METADATA, " \t ")),
    ])
    def test_unspecified_metadata_preserves_existing_values(self, name, metadata):
        test = self.test
        importer = DefaultReImporter(test=test, scan_type="ZAP Scan", **metadata)
        importer.update_test_meta()
        self.assertEqual({field: getattr(test, field) for field in METADATA}, METADATA)

    def test_nonempty_metadata_keeps_surrounding_whitespace(self):
        test = self.test
        supplied = {field: f" {value} " for field, value in METADATA.items()}
        importer = DefaultReImporter(test=test, scan_type="ZAP Scan", **supplied)
        importer.update_test_meta()
        self.assertEqual({field: getattr(test, field) for field in METADATA}, supplied)
