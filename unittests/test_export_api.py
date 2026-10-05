import uuid

from django.core.files.base import ContentFile
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo import __version__
from dojo.export import rows
from dojo.location.feature import locations_enabled
from dojo.models import (
    Dojo_User,
    Engagement,
    FileUpload,
    Finding,
    Finding_Group,
    Notes,
    Product,
    Product_Type,
    Risk_Acceptance,
    System_Settings,
    Test,
)
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


class InstanceIdTest(DojoTestCase):
    def test_instance_id_is_a_stable_uuid(self):
        first = System_Settings.objects.get().instance_id
        self.assertIsInstance(first, uuid.UUID)

        row = System_Settings.objects.get(no_cache=True)
        row.save()

        self.assertEqual(System_Settings.objects.get().instance_id, first)


def token_client(username):
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION="Token " + Token.objects.get(user__username=username).key)
    return client


@versioned_fixtures
class ExportManifestBasicsTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def test_manifest_rejects_anonymous_requests(self):
        response = APIClient().get(reverse("export-manifest"))
        self.assertIn(response.status_code, {401, 403})

    def test_manifest_rejects_non_superusers(self):
        response = token_client("user1").get(reverse("export-manifest"))
        self.assertEqual(response.status_code, 403, response.content[:500])

    def test_manifest_reports_version_and_instance(self):
        response = token_client("admin").get(reverse("export-manifest"))
        self.assertEqual(response.status_code, 200, response.content[:500])
        body = response.json()
        self.assertEqual(body["export_api_version"], 1)
        self.assertEqual(body["defectdojo_version"], __version__)
        self.assertEqual(body["instance_id"], str(System_Settings.objects.get().instance_id))
        self.assertEqual(body["locations_enabled"], locations_enabled())
        self.assertEqual(response["X-DefectDojo-Export-Version"], "1")

    def test_manifest_rejects_a_bad_file_cap(self):
        response = token_client("admin").get(reverse("export-manifest"), {"max_file_bytes": "lots"})
        self.assertEqual(response.status_code, 400)


@versioned_fixtures
class ExportManifestContentTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def manifest(self, **params):
        response = token_client("admin").get(reverse("export-manifest"), params)
        self.assertEqual(response.status_code, 200, response.content[:500])
        return response.json()

    def test_counts_match_the_database(self):
        counts = self.manifest()["counts"]
        self.assertEqual(counts["product_types"], Product_Type.objects.count())
        self.assertEqual(counts["products"], Product.objects.count())
        self.assertEqual(counts["engagements"], Engagement.objects.count())
        self.assertEqual(counts["tests"], Test.objects.count())
        self.assertEqual(counts["findings"], Finding.objects.filter(duplicate=False).count())
        self.assertEqual(counts["duplicate_findings"], Finding.objects.filter(duplicate=True).count())
        self.assertEqual(counts["notes"], Notes.objects.count())
        self.assertEqual(counts["files"], FileUpload.objects.count())
        self.assertEqual(counts["risk_acceptances"], Risk_Acceptance.objects.count())
        self.assertEqual(counts["finding_groups"], Finding_Group.objects.count())

    def test_products_list_every_product(self):
        listed = {entry["id"]: entry for entry in self.manifest()["products"]}
        self.assertEqual(set(listed), set(Product.objects.values_list("id", flat=True)))
        product = Product.objects.order_by("id").first()
        entry = listed[product.id]
        self.assertEqual(entry["name"], product.name)
        self.assertEqual(entry["prod_type"], product.prod_type.name)
        self.assertEqual(
            entry["findings"],
            Finding.objects.filter(test__engagement__product=product, duplicate=False).count(),
        )

    def test_users_are_only_the_referenced_ones(self):
        Dojo_User.objects.create(username="never-referenced")
        usernames = {user["username"] for user in self.manifest()["users"]}
        self.assertNotIn("never-referenced", usernames)
        reporter = Finding.objects.order_by("id").first().reporter.username
        self.assertIn(reporter, usernames)

    def test_scan_types_count_tests_and_findings(self):
        scan_types = {entry["name"]: entry for entry in self.manifest()["scan_types"]}
        test = Test.objects.order_by("id").first()
        self.assertIn(test.test_type.name, scan_types)
        self.assertGreaterEqual(scan_types[test.test_type.name]["tests"], 1)

    def test_oversized_files_are_listed(self):
        finding = Finding.objects.order_by("id").first()
        upload = FileUpload(title="capture")
        upload.file.save("capture.bin", ContentFile(b"0123456789"), save=True)
        finding.files.add(upload)
        oversized = self.manifest(max_file_bytes=5)["oversized_files"]
        self.assertIn(
            {"id": upload.id, "title": "capture", "size": 10, "owner": "finding", "owner_id": finding.id},
            oversized,
        )

    def test_dedupe_settings_cover_used_scan_types(self):
        manifest = self.manifest()
        used = {entry["name"] for entry in manifest["scan_types"]}
        self.assertEqual(set(manifest["dedupe"]), used)
        for entry in manifest["dedupe"].values():
            self.assertIn("algorithm", entry)
            self.assertIn("hash_fields", entry)

    def test_not_exported_lists_settings_that_stay_behind(self):
        self.assertEqual(
            self.manifest()["not_exported"],
            [
                "api_tokens",
                "sso_settings",
                "jira_instances",
                "tool_configurations",
                "notification_settings",
                "system_settings",
                "api_scan_configurations",
                "threat_model_files",
                "non_url_locations",
            ],
        )


@versioned_fixtures
class ExportRowsTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def test_product_row_uses_names_and_usernames(self):
        product = Product.objects.order_by("id").first()
        product.product_manager = Dojo_User.objects.get(username="admin")
        product.save()
        row = rows.product_row(product)
        self.assertEqual(row["name"], product.name)
        self.assertEqual(row["prod_type"]["name"], product.prod_type.name)
        self.assertEqual(row["product_manager"], "admin")
        self.assertEqual(row["sla_configuration"], product.sla_configuration.name)
        self.assertNotIn("id", row)

    def test_engagement_row_has_every_scalar_column(self):
        engagement = Engagement.objects.order_by("id").first()
        row = rows.engagement_row(engagement, max_file_bytes=1024)
        for name in ("name", "description", "target_start", "target_end", "status", "engagement_type",
                     "build_id", "commit_hash", "branch_tag", "source_code_management_uri",
                     "deduplication_on_engagement", "created"):
            self.assertIn(name, row)
        self.assertEqual(row["lead"], engagement.lead.username if engagement.lead else None)
        self.assertEqual(row["notes"], [rows.note_row(note) for note in engagement.notes.all()])

    def test_test_row_names_its_lookups(self):
        test = Test.objects.order_by("id").first()
        row = rows.test_row(test, max_file_bytes=1024)
        self.assertEqual(row["test_type"], test.test_type.name)
        self.assertEqual(row["scan_type"], test.scan_type)
        self.assertEqual(row["environment"], test.environment.name if test.environment else None)

    def test_note_row_keeps_author_and_privacy(self):
        note = Notes.objects.order_by("id").first()
        self.assertEqual(
            rows.note_row(note),
            {
                "id": str(note.id),
                "entry": note.entry,
                "date": note.date.isoformat(),
                "author": note.author.username,
                "private": note.private,
                "edited": note.edited,
                "editor": note.editor.username if note.editor else None,
                "edit_time": note.edit_time.isoformat() if note.edit_time else None,
                "note_type": note.note_type.name if note.note_type else None,
            },
        )

    def test_file_row_lists_a_small_file_without_its_bytes(self):
        upload = FileUpload(title="small")
        upload.file.save("small.txt", ContentFile(b"hello"), save=True)
        row = rows.file_row(upload.id, upload.title, upload.file, max_file_bytes=1024)
        self.assertEqual((row["id"], row["title"], row["size"]), (str(upload.id), "small", 5))
        self.assertNotIn("omitted", row)

    def test_file_row_skips_big_files(self):
        upload = FileUpload(title="big")
        upload.file.save("big.txt", ContentFile(b"hello"), save=True)
        row = rows.file_row(upload.id, upload.title, upload.file, max_file_bytes=4)
        self.assertEqual(row["omitted"], "too_large")

    def test_file_row_marks_missing_file(self):
        upload = FileUpload(title="gone")
        upload.file.save("gone.txt", ContentFile(b"x"), save=True)
        upload.file.storage.delete(upload.file.name)
        row = rows.file_row(upload.id, upload.title, upload.file, max_file_bytes=1024)
        self.assertEqual(row["omitted"], "missing")
