import base64
import datetime
import json
import re
import uuid
from unittest.mock import patch

from django.core.files.base import ContentFile
from django.db import connection
from django.db.models import Count
from django.db.models.fields.files import FieldFile
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo import __version__
from dojo.export import rows, services
from dojo.location.feature import locations_enabled
from dojo.location.models import Location, LocationFindingReference
from dojo.models import (
    BurpRawRequestResponse,
    Dojo_User,
    DojoMeta,
    Endpoint_Status,
    Engagement,
    FileUpload,
    Finding,
    Finding_CWE,
    Finding_Group,
    FindingVulnerabilityReference,
    Notes,
    Product,
    Product_Type,
    Risk_Acceptance,
    System_Settings,
    Test,
    Vulnerability,
)
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


class InstanceIdTest(DojoTestCase):
    def test_instance_id_is_a_stable_uuid(self):
        first = System_Settings.objects.get().instance_id
        self.assertIsInstance(first, uuid.UUID)

        row = System_Settings.objects.get(no_cache=True)
        row.save()

        self.assertEqual(System_Settings.objects.get().instance_id, first)

    def test_export_reads_the_stored_instance_id_or_fails(self):
        stored = str(System_Settings.objects.get(no_cache=True).instance_id)
        self.assertEqual([services.instance_id(), services.instance_id()], [stored, stored])
        System_Settings.objects.all().delete()
        with self.assertRaises(System_Settings.DoesNotExist):
            services.instance_id()


def token_client(username):
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION="Token " + Token.objects.get(user__username=username).key)
    return client


def finding_row(finding):
    finding = Finding.objects.prefetch_related(*rows.finding_prefetch()).get(pk=finding.pk)
    [(finding, pairs, omitted)] = rows.with_pairs([finding], services.DEFAULT_MAX_PAIR_BYTES)
    return rows.finding_row(finding, 1024, pairs, omitted)


def add_pair(finding, text):
    return BurpRawRequestResponse.objects.create(finding=finding, burpRequestBase64=text, burpResponseBase64=text)


def pair_reads(queries):
    reads = []
    for query in queries.captured_queries:
        sql = re.sub(r"LENGTH\([^)]*\)", "", query["sql"])
        if "burpRequestBase64" in sql or "burpResponseBase64" in sql:
            match = re.search(r'"dojo_burprawrequestresponse"\."id" IN \(([^)]*)\)', sql)
            reads.append({int(pair_id) for pair_id in re.findall(r"\d+", match.group(1))} if match else sql)
    return reads


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


@versioned_fixtures
class ExportFindingRowTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def finding(self):
        return Finding.objects.order_by("id").first()

    def test_finding_row_has_every_scalar_column(self):
        finding = self.finding()
        row = finding_row(finding)
        expected = {
            field.name
            for field in Finding._meta.concrete_fields
            if not field.is_relation and field.name not in rows.FINDING_SKIP
        }
        self.assertEqual(set(row["fields"]), expected)
        self.assertEqual(row["hash_code"], finding.hash_code)
        self.assertEqual(row["users"]["reporter"], finding.reporter.username)

    def test_finding_row_keeps_null_columns(self):
        finding = self.finding()
        Finding.objects.filter(pk=finding.pk).update(cwe=None, line=None, file_path=None)
        finding.refresh_from_db()
        fields = finding_row(finding)["fields"]
        self.assertIsNone(fields["cwe"])
        self.assertIsNone(fields["line"])
        self.assertIsNone(fields["file_path"])

    def test_finding_row_carries_side_data(self):
        finding = self.finding()
        finding.tags = "alpha, beta"
        finding.save()
        DojoMeta.objects.create(finding=finding, name="team", value="payments")
        BurpRawRequestResponse.objects.create(
            finding=finding,
            burpRequestBase64=base64.b64encode(b"GET / HTTP/1.1"),
            burpResponseBase64=base64.b64encode(b"HTTP/1.1 200 OK"),
        )
        vulnerability = Vulnerability.objects.create(vulnerability_id="CVE-2024-0001")
        FindingVulnerabilityReference.objects.create(finding=finding, vulnerability=vulnerability)
        Finding_CWE.objects.create(finding=finding, cwe="CWE-79")
        row = finding_row(finding)
        self.assertEqual(row["tags"], ["alpha", "beta"])
        self.assertEqual(row["meta"], [{"name": "team", "value": "payments"}])
        pair = row["request_response"][0]
        self.assertEqual(base64.b64decode(pair["request_b64"]), b"GET / HTTP/1.1")
        self.assertEqual(base64.b64decode(pair["response_b64"]), b"HTTP/1.1 200 OK")
        self.assertEqual(row["request_response_omitted"], 0)
        self.assertEqual(row["vulnerability_ids"], ["CVE-2024-0001"])
        self.assertEqual(row["cwes"], ["CWE-79"])


@override_settings(V3_FEATURE_LOCATIONS=False)
class ExportFindingRowEndpointModeTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def test_endpoint_status_maps_to_a_location_status(self):
        status = Endpoint_Status.objects.order_by("id").first()
        Endpoint_Status.objects.filter(pk=status.pk).update(
            mitigated=True, mitigated_by=Dojo_User.objects.get(username="admin"),
        )
        row = finding_row(status.finding)
        entry = next(item for item in row["locations"] if item["value"] == str(status.endpoint))
        self.assertEqual(entry["type"], "url")
        self.assertEqual(entry["status"], "Mitigated")
        self.assertEqual(entry["actor"], "admin")
        self.assertEqual(entry["date"], status.date.isoformat())

    def test_risk_accepted_outranks_false_positive(self):
        status = Endpoint_Status.objects.order_by("id").first()
        Endpoint_Status.objects.filter(pk=status.pk).update(risk_accepted=True, false_positive=True)
        row = finding_row(status.finding)
        entry = next(item for item in row["locations"] if item["value"] == str(status.endpoint))
        self.assertEqual(entry["status"], "RiskAccepted")


@override_settings(V3_FEATURE_LOCATIONS=True)
class ExportFindingRowLocationsModeTest(DojoTestCase):
    fixtures = ["dojo_testdata_locations.json"]

    def test_location_reference_keeps_its_status(self):
        reference = LocationFindingReference.objects.order_by("id").first()
        created_at = datetime.datetime(2024, 3, 14, 23, 30, tzinfo=datetime.UTC)
        LocationFindingReference.objects.filter(pk=reference.pk).update(
            status="FalsePositive", created=created_at,
        )
        row = finding_row(reference.finding)
        entry = next(item for item in row["locations"] if item["value"] == str(reference.location))
        self.assertEqual(entry["status"], "FalsePositive")
        expected_date = timezone.localdate(created_at, timezone.get_default_timezone())
        self.assertEqual(entry["date"], expected_date.isoformat())

    def test_non_url_location_is_not_exported(self):
        reference = LocationFindingReference.objects.order_by("id").first()
        package = Location.objects.create(location_type="package", location_value="pkg:npm/demo@1.0.0")
        LocationFindingReference.objects.create(location=package, finding=reference.finding)
        row = finding_row(reference.finding)
        self.assertNotIn("pkg:npm/demo@1.0.0", [item["value"] for item in row["locations"]])


def ndjson(response):
    body = b"".join(response.streaming_content).decode()
    return [json.loads(line) for line in body.splitlines() if line]


@versioned_fixtures
class ExportProductStreamTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.client = token_client("admin")
        self.product = Product.objects.annotate(n=Count("engagement__test__finding")).order_by("-n").first()

    def page(self, **params):
        response = self.client.get(reverse("export-products", kwargs={"product_id": self.product.id}), params)
        self.assertEqual(response.status_code, 200, getattr(response, "content", b"")[:500])
        self.assertEqual(response["Content-Type"], "application/x-ndjson")
        return ndjson(response)

    def walk(self, cursor="", **params):
        lines = []
        for _ in range(500):
            page = self.page(cursor=cursor, **params)
            self.assertEqual(page[0]["kind"], "header")
            lines.extend(page[1:-1])
            if page[-1]["kind"] == "end":
                return lines, page[-1]["counts"]
            self.assertEqual(page[-1]["kind"], "page")
            cursor = page[-1]["next"]
        self.fail("export never reached its end line")
        return None

    def ids(self, lines, kind):
        return [line["id"] for line in lines if line["kind"] == kind]

    def test_one_page_holds_the_whole_small_product(self):
        lines, counts = self.walk()
        findings = Finding.objects.filter(test__engagement__product=self.product, duplicate=False)
        self.assertEqual(sorted(self.ids(lines, "finding")), sorted(findings.values_list("id", flat=True)))
        self.assertEqual(counts["findings"], findings.count())
        self.assertEqual(self.ids(lines, "product"), [self.product.id])
        self.assertEqual(
            sorted(self.ids(lines, "engagement")),
            sorted(Engagement.objects.filter(product=self.product).values_list("id", flat=True)),
        )

    def test_small_pages_give_the_same_findings(self):
        full, _ = self.walk()
        paged, _ = self.walk(limit=2)
        self.assertEqual(self.ids(paged, "finding"), self.ids(full, "finding"))
        self.assertEqual(len(self.ids(paged, "finding")), len(set(self.ids(paged, "finding"))))

    def test_every_test_appears_even_without_findings(self):
        engagement = Engagement.objects.filter(product=self.product).first()
        empty = Test.objects.create(
            engagement=engagement,
            test_type=Test.objects.first().test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        lines, _ = self.walk()
        self.assertIn(empty.id, self.ids(lines, "test"))

    def test_duplicates_are_skipped_by_default(self):
        finding = Finding.objects.filter(test__engagement__product=self.product).order_by("id").first()
        Finding.objects.filter(pk=finding.pk).update(duplicate=True)
        lines, _ = self.walk()
        self.assertNotIn(finding.id, self.ids(lines, "finding"))
        lines, _ = self.walk(include_duplicates="true")
        self.assertIn(finding.id, self.ids(lines, "finding"))

    def test_cursor_survives_deleted_test(self):
        page, cursor, state = self.page(limit=1), "", None
        while page[-1]["kind"] == "page":
            cursor = page[-1]["next"]
            state = json.loads(base64.urlsafe_b64decode(cursor))
            if state["p"] == "tests" and state["t"]:
                break
            page = self.page(limit=1, cursor=cursor)
        self.assertIsNotNone(state, "the fixture product needs more than one object line")
        Test.objects.filter(pk=state["t"]).delete()
        follow = self.page(limit=1000, cursor=cursor)
        self.assertEqual(follow[-1]["kind"], "end")

    def test_one_line_pages_give_the_same_findings(self):
        full, _ = self.walk()
        paged, _ = self.walk(limit=1)
        self.assertEqual(self.ids(paged, "finding"), self.ids(full, "finding"))
        self.assertEqual(self.ids(paged, "test"), self.ids(full, "test"))

    def test_finding_added_during_the_walk_is_neither_sent_nor_counted(self):
        first = self.page(limit=1)
        self.assertEqual(first[-1]["kind"], "page")
        added = Finding(
            test=Test.objects.get(pk=self.ids(first, "test")[-1]),
            title="added during the walk",
            severity="High",
            reporter=Dojo_User.objects.get(username="admin"),
        )
        added.save(dedupe_option=False)
        rest, counts = self.walk(cursor=first[-1]["next"], limit=1)
        sent = self.ids(first, "finding") + self.ids(rest, "finding")
        self.assertNotIn(added.id, sent)
        self.assertEqual(len(sent), counts["findings"])

    def test_a_page_of_findings_runs_a_fixed_number_of_queries(self):
        test = Test.objects.filter(engagement__product=self.product).annotate(n=Count("finding")).order_by("-n").first()
        for finding in Finding.objects.filter(test=test):
            add_pair(finding, base64.b64encode(b"a" * 30))
        high = Finding.objects.order_by("-id").values_list("id", flat=True).first()
        cursor = services.Cursor(services.TESTS, test_id=test.id, high=high)
        options = services.ExportOptions(limit=test.n, include_duplicates=True)
        with self.assertNumQueries(20):
            lines = [json.loads(line) for line in services.product_page(self.product, cursor, options)]
        self.assertEqual(len(self.ids(lines, "finding")), test.n)
        self.assertTrue(all(line["data"]["request_response"] for line in lines if line["kind"] == "finding"))

    def findings_without_pairs(self):
        BurpRawRequestResponse.objects.all().delete()
        return list(Finding.objects.filter(test__engagement__product=self.product, duplicate=False).order_by("id")[:2])

    def finding_data(self, **params):
        lines, _ = self.walk(**params)
        return {line["id"]: line["data"] for line in lines if line["kind"] == "finding"}

    def test_pairs_past_the_budget_are_left_out_as_a_prefix(self):
        finding = self.findings_without_pairs()[0]
        texts = [base64.b64encode(char * size) for char, size in ((b"a", 30), (b"b", 300), (b"c", 30))]
        for text in texts:
            add_pair(finding, text)
        sent = [{"request_b64": text.decode(), "response_b64": text.decode()} for text in texts]
        for budget, kept in ((79, 0), (80, 1), (879, 1), (880, 2), (960, 3)):
            with self.subTest(max_pair_bytes=budget):
                data = self.finding_data(max_pair_bytes=budget)[finding.id]
                self.assertEqual(data["request_response"], sent[:kept])
                self.assertEqual(data["request_response_omitted"], 3 - kept)

    def test_a_zero_pair_budget_leaves_out_every_pair(self):
        first, second = self.findings_without_pairs()
        add_pair(first, base64.b64encode(b"a" * 30))
        add_pair(second, b"")
        data = self.finding_data(max_pair_bytes=0)
        self.assertEqual([data[first.id]["request_response"], data[second.id]["request_response"]], [[], []])
        omitted = {finding_id: row["request_response_omitted"] for finding_id, row in data.items()}
        self.assertEqual(omitted, {finding_id: 1 if finding_id in {first.id, second.id} else 0 for finding_id in data})

    def test_the_default_pair_budget_is_16_mib(self):
        self.assertEqual(services.ExportOptions().max_pair_bytes, 16 * 1024 * 1024)
        with patch.object(services, "product_page", wraps=services.product_page) as product_page:
            self.page()
        self.assertEqual(product_page.call_args.args[2].max_pair_bytes, 16 * 1024 * 1024)

    def test_a_bad_pair_budget_is_rejected(self):
        url = reverse("export-products", kwargs={"product_id": self.product.id})
        for value in ("lots", "-1", "67108865"):
            with self.subTest(max_pair_bytes=value), self.assertLogs("django.request", level="WARNING"):
                self.assertEqual(self.client.get(url, {"max_pair_bytes": value}).status_code, 400)
        for value in ("0", "67108864"):
            self.assertEqual(self.page(max_pair_bytes=value)[-1]["kind"], "end")

    def test_left_out_pairs_are_never_read(self):
        first, second = self.findings_without_pairs()
        kept = add_pair(first, base64.b64encode(b"a" * 30))
        add_pair(first, base64.b64encode(b"b" * 300))
        add_pair(first, base64.b64encode(b"c" * 30))
        later = add_pair(second, base64.b64encode(b"d" * 30))
        with CaptureQueriesContext(connection) as queries:
            data = self.finding_data(max_pair_bytes=100)
        self.assertEqual([data[first.id]["request_response_omitted"], data[second.id]["request_response_omitted"]], [2, 0])
        self.assertCountEqual(pair_reads(queries), [{kept.id}, {later.id}])

    def test_groups_and_risk_acceptances_come_last(self):
        test = Test.objects.filter(engagement__product=self.product).order_by("id").first()
        finding = Finding.objects.filter(test=test, duplicate=False).order_by("id").first()
        admin = Dojo_User.objects.get(username="admin")
        group = Finding_Group.objects.create(name="group", test=test, creator=admin)
        group.findings.add(finding)
        acceptance = Risk_Acceptance.objects.create(name="accepted", owner=admin)
        acceptance.accepted_findings.add(finding)
        test.engagement.risk_acceptance.add(acceptance)
        lines, counts = self.walk(limit=1)
        self.assertEqual([line["kind"] for line in lines[-2:]], ["finding_group", "risk_acceptance"])
        self.assertEqual(lines[-2]["data"]["finding_ids"], [finding.id])
        self.assertEqual(lines[-1]["data"]["accepted_finding_ids"], [finding.id])
        self.assertEqual(lines[-1]["data"]["engagement_ids"], [test.engagement_id])
        self.assertEqual((counts["finding_groups"], counts["risk_acceptances"]), (1, 1))

    def test_bad_requests_are_rejected(self):
        url = reverse("export-products", kwargs={"product_id": self.product.id})
        self.assertEqual(self.client.get(url, {"cursor": "not-a-cursor"}).status_code, 400)
        self.assertEqual(self.client.get(url, {"limit": "0"}).status_code, 400)
        missing = reverse("export-products", kwargs={"product_id": 999999})
        self.assertEqual(self.client.get(missing).status_code, 404)
        self.assertEqual(token_client("user1").get(url).status_code, 403)


@versioned_fixtures
class ExportFileDownloadTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def upload(self):
        upload = FileUpload(title="capture")
        upload.file.save("capture.txt", ContentFile(b"hello"), save=True)
        return upload

    def test_file_bytes_download(self):
        response = token_client("admin").get(reverse("export-files", kwargs={"file_id": self.upload().id}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/octet-stream")
        self.assertEqual(b"".join(response.streaming_content), b"hello")

    def acceptance(self):
        acceptance = Risk_Acceptance.objects.create(name="proof test", owner=Dojo_User.objects.get(username="admin"))
        acceptance.path.save("proof.pdf", ContentFile(b"%PDF-"), save=True)
        return acceptance

    def test_risk_acceptance_proof_download(self):
        response = token_client("admin").get(reverse("export-proof", kwargs={"acceptance_id": self.acceptance().id}))
        self.assertEqual(b"".join(response.streaming_content), b"%PDF-")

    def test_file_gone_from_storage_is_404(self):
        upload = self.upload()
        upload.file.storage.delete(upload.file.name)
        response = token_client("admin").get(reverse("export-files", kwargs={"file_id": upload.id}))
        self.assertEqual(response.status_code, 404)

    def test_proof_gone_from_storage_is_404(self):
        acceptance = self.acceptance()
        acceptance.path.storage.delete(acceptance.path.name)
        response = token_client("admin").get(reverse("export-proof", kwargs={"acceptance_id": acceptance.id}))
        self.assertEqual(response.status_code, 404)

    def test_storage_errors_other_than_a_missing_file_are_not_hidden(self):
        upload = self.upload()
        with (
            patch.object(FieldFile, "open", side_effect=PermissionError("denied")),
            self.assertLogs("dojo.api_v2.exception_handler", level="ERROR"),
            self.assertLogs("django.request", level="ERROR"),
        ):
            response = token_client("admin").get(reverse("export-files", kwargs={"file_id": upload.id}))
            self.assertEqual(response.status_code, 500)

    def test_missing_file_is_404_and_users_are_refused(self):
        self.assertEqual(token_client("admin").get(reverse("export-files", kwargs={"file_id": 999999})).status_code, 404)
        self.assertEqual(token_client("user1").get(reverse("export-files", kwargs={"file_id": self.upload().id})).status_code, 403)
