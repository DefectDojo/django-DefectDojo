import base64
from types import SimpleNamespace
from unittest.mock import patch

import requests
from django.test import SimpleTestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient, APITestCase

from dojo.finding.prisma_images_identity import EngineImageClient, EngineLookupError, migrate_engagement, prepare_finding_identity, run_bulk_migration
from dojo.finding.serializer import PrismaEngagementIdentityMigrationSerializer
from dojo.models import Engagement, Finding, User
from dojo.models import Test as ScanTest


class PrismaIdentityTests(SimpleTestCase):
    suffix = "CVE-1,high,openssl,1,9.00,fixed"
    image = "registry/app:v1"

    def finding(self):
        identity = "registry/app@sha256:old," + self.suffix
        return SimpleNamespace(
            unique_id_from_tool=base64.b64encode(identity.encode()).decode(),
            mitigation="fixed",
            impact="Registry: registry\nRepository: app\nImage ID: sha256:old",
            description="<p><strong>Tag:</strong> v1</p><p><strong>Cloud Id:</strong> sha256:old</p>"
                        "<p><strong>Custom Id:</strong> " + identity + "</p><p>Keep this note</p>",
        )

    def test_orders_pairs_and_preserves_original_vulnerability_values(self):
        result = prepare_finding_identity(self.finding(), [self.image], {
            self.image: [("deploy-2", "container-2"), ("deploy-1", "container-1"), ("deploy-1", "container-1")],
        })
        self.assertEqual("registry/app@deploy-1,container-1,deploy-2,container-2," + self.suffix,
                         base64.b64decode(result["unique_id_from_tool"]).decode())
        self.assertIn("Deployment:</strong> deploy-1,deploy-2", result["description"])
        self.assertIn("Container Name:</strong> container-1,container-2", result["description"])
        self.assertIn("Keep this note", result["description"])

    def test_no_runtime_images_uses_two_empty_fields_like_extractor(self):
        result = prepare_finding_identity(self.finding(), [], {})
        self.assertEqual("registry/app@,," + self.suffix, base64.b64decode(result["unique_id_from_tool"]).decode())
        self.assertEqual(0, result["deployment_count"])

    def test_runtime_image_without_deployments_uses_empty_fields(self):
        result = prepare_finding_identity(self.finding(), [self.image], {})
        self.assertEqual("registry/app@,," + self.suffix, base64.b64decode(result["unique_id_from_tool"]).decode())

    def test_deployment_migration_updates_impact_without_duplicate_or_stale_fields(self):
        finding = self.finding()
        finding.impact += "\nDeployment: old\nContainer Name: old\nDeployment: duplicate\nKeep this note"
        result = prepare_finding_identity(finding, [self.image], {
            self.image: [("deploy-2", "container-2"), ("deploy-1", "container-1")],
        })
        self.assertEqual(
            "Registry: registry\nRepository: app\nImage ID: sha256:old\nKeep this note\n"
            "Deployment: deploy-1,deploy-2\nContainer Name: container-1,container-2",
            result["impact"],
        )
        finding.unique_id_from_tool = result["unique_id_from_tool"]
        finding.description = result["description"]
        finding.impact = result["impact"]
        self.assertEqual(result, prepare_finding_identity(finding, [self.image], {
            self.image: [("deploy-2", "container-2"), ("deploy-1", "container-1")],
        }))

    def test_id_and_empty_runtime_remove_impact_deployment_fields(self):
        for migration_type in ("ID", "DeploymentContainerName"):
            with self.subTest(migration_type=migration_type):
                finding = self.finding()
                finding.impact += "\nDeployment: old\nContainer Name: old\nKeep this note"
                result = prepare_finding_identity(finding, [], {}, migration_type=migration_type)
                self.assertEqual(
                    "Registry: registry\nRepository: app\nImage ID: sha256:old\nKeep this note",
                    result["impact"],
                )

    def test_repeated_migration_is_idempotent(self):
        finding = self.finding()
        first = prepare_finding_identity(finding, [self.image], {self.image: [("deploy-1", "container-1")]})
        finding.unique_id_from_tool = first["unique_id_from_tool"]
        finding.description = first["description"]
        second = prepare_finding_identity(finding, [self.image], {self.image: [("deploy-1", "container-1")]})
        self.assertEqual(first, second)

    def test_old_tag_can_use_unambiguous_runtime_deployments(self):
        image = "registry/app:v2"
        result = prepare_finding_identity(self.finding(), [image], {image: [("deploy-1", "container-1")]})
        self.assertEqual(1, result["deployment_count"])

    def test_ambiguous_runtime_tags_are_not_migrated(self):
        with self.assertRaisesRegex(ValueError, "different deployments"):
            prepare_finding_identity(self.finding(), ["registry/app:v2", "registry/app:v3"], {
                "registry/app:v2": [("deploy-1", "container-1")],
                "registry/app:v3": [("deploy-2", "container-2")],
            })

    def test_comma_in_package_and_original_cvss_are_preserved(self):
        finding = self.finding()
        suffix = "CVE-1,high,lib-one,lib-two,1,9.00,fixed"
        finding.unique_id_from_tool = base64.b64encode(("registry/app@sha256:old," + suffix).encode()).decode()
        result = prepare_finding_identity(finding, [], {})
        self.assertEqual("registry/app@,," + suffix, base64.b64decode(result["unique_id_from_tool"]).decode())

    def test_unsorted_packages_are_sorted_in_identity_and_description(self):
        finding = self.finding()
        finding.unique_id_from_tool = base64.b64encode(
            b"registry/app@sha256:old,CVE-1,high,zlib1g-dev,zlib1g,1,9.00,fixed").decode()
        finding.description += "<p><strong>Data Packages:</strong> zlib1g-dev,zlib1g</p>"
        result = prepare_finding_identity(finding, [], {})
        self.assertEqual("registry/app@,,CVE-1,high,zlib1g,zlib1g-dev,1,9.00,fixed",
                         base64.b64decode(result["unique_id_from_tool"]).decode())
        self.assertIn("Data Packages:</strong> zlib1g,zlib1g-dev", result["description"])

    def test_commas_in_fix_status_preserve_identity_and_packages(self):
        fix_status = (
            "fixed in 1.82.2, 1.83.2, 1.84.0-dev.0.20260825144003-d5a41119e0e3, "
            "1.85.0-dev.0.20260825072537-93e31b48545e"
        )
        package = "google.golang.org/grpc/internal/transport"
        for packages in (package, "zlib," + package):
            for migration_type, prefix in (("ID", "registry/app@sha256:old,"),
                                           ("DeploymentContainerName", "registry/app@,,")):
                with self.subTest(packages=packages, migration_type=migration_type):
                    finding = self.finding()
                    finding.mitigation = fix_status
                    suffix = f"CVE-2026-84445,high,{packages},v1.82.0,0.00,{fix_status}"
                    finding.unique_id_from_tool = base64.b64encode(
                        ("registry/app@sha256:old," + suffix).encode(),
                    ).decode()
                    finding.description += f"<p><strong>Data Packages:</strong> {packages}</p>"
                    result = prepare_finding_identity(finding, [], {}, migration_type=migration_type)
                    expected_packages = package if packages == package else package + ",zlib"
                    identity = prefix + f"CVE-2026-84445,high,{expected_packages},v1.82.0,0.00,{fix_status}"
                    self.assertEqual(identity, base64.b64decode(result["unique_id_from_tool"]).decode())
                    self.assertIn("Custom Id:</strong> " + identity, result["description"])
                    self.assertIn(f"Data Packages:</strong> {expected_packages}</p>", result["description"])
                    finding.unique_id_from_tool = result["unique_id_from_tool"]
                    finding.description = result["description"]
                    finding.impact = result["impact"]
                    self.assertEqual(result, prepare_finding_identity(finding, [], {}, migration_type=migration_type))

    def test_empty_fix_status_preserves_identity(self):
        for fix_status in ("", None):
            with self.subTest(fix_status=fix_status):
                finding = self.finding()
                finding.mitigation = fix_status
                suffix = "CVE-1,high,openssl,1,9.00,"
                finding.unique_id_from_tool = base64.b64encode(("registry/app@sha256:old," + suffix).encode()).decode()
                result = prepare_finding_identity(finding, [], {})
                self.assertEqual("registry/app@,," + suffix, base64.b64decode(result["unique_id_from_tool"]).decode())

    def test_mismatched_fix_status_is_rejected(self):
        finding = self.finding()
        finding.mitigation = "fixed in 1, 2"
        with self.assertRaisesRegex(ValueError, "does not match the stored Fix Status"):
            prepare_finding_identity(finding, [], {})

    def test_deployment_identity_can_be_migrated_back_to_cloud_id(self):
        finding = self.finding()
        finding.unique_id_from_tool = base64.b64encode(
            ("registry/app@sha256:old,CVE-1,high,lib-one,lib-two,1,9.00,fixed").encode(),
        ).decode()
        original_id = finding.unique_id_from_tool
        deployed = prepare_finding_identity(finding, [self.image], {
            self.image: [("deploy-2", "container-2"), ("deploy-1", "container-1")],
        })
        finding.unique_id_from_tool = deployed["unique_id_from_tool"]
        finding.description = deployed["description"]
        result = prepare_finding_identity(finding, [], {}, migration_type="ID")
        self.assertEqual(original_id, result["unique_id_from_tool"])
        self.assertNotIn("Deployment:", result["description"])
        self.assertNotIn("Container Name:", result["description"])
        self.assertIn("Keep this note", result["description"])
        self.assertIn("Custom Id:</strong> registry/app@sha256:old,", result["description"])
        finding.unique_id_from_tool = result["unique_id_from_tool"]
        finding.description = result["description"]
        self.assertEqual(result, prepare_finding_identity(finding, [], {}, migration_type="ID"))
        self.assertEqual(deployed, prepare_finding_identity(finding, [self.image], {
            self.image: [("deploy-2", "container-2"), ("deploy-1", "container-1")],
        }))

    def test_empty_deployment_identity_can_be_migrated_to_cloud_id(self):
        finding = self.finding()
        original_id = finding.unique_id_from_tool
        deployed = prepare_finding_identity(finding, [], {})
        finding.unique_id_from_tool = deployed["unique_id_from_tool"]
        finding.description = deployed["description"]
        result = prepare_finding_identity(finding, [], {}, migration_type="ID")
        self.assertEqual(original_id, result["unique_id_from_tool"])
        self.assertNotIn("Deployment:", result["description"])
        self.assertNotIn("Container Name:", result["description"])

    def test_id_migration_removes_each_existing_deployment_field(self):
        for name in ("Deployment", "Container Name"):
            with self.subTest(name=name):
                finding = self.finding()
                finding.description += f"<p><strong>{name}:</strong> old-value</p>"
                result = prepare_finding_identity(finding, [], {}, migration_type="ID")
                self.assertEqual(finding.unique_id_from_tool, result["unique_id_from_tool"])
                self.assertNotIn(name + ":", result["description"])
                self.assertIn("Keep this note", result["description"])

    def test_id_migration_uses_impact_image_id_when_cloud_field_is_absent(self):
        finding = self.finding()
        finding.description = "<p>Keep this note</p>"
        result = prepare_finding_identity(finding, [], {}, migration_type="ID")
        self.assertEqual(finding.unique_id_from_tool, result["unique_id_from_tool"])
        self.assertNotIn("Deployment:", result["description"])
        self.assertIn("Keep this note", result["description"])

    def test_id_migration_without_cloud_id_is_rejected(self):
        finding = self.finding()
        finding.description = "<p>Keep this note</p>"
        finding.impact = "Registry: registry\nRepository: app"
        finding.unique_id_from_tool = base64.b64encode(("registry/app@,," + self.suffix).encode()).decode()
        with self.assertRaisesRegex(ValueError, "Cloud Id or Image ID is required"):
            prepare_finding_identity(finding, [], {}, migration_type="ID")

    def test_unsupported_migration_type_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported migration type"):
            prepare_finding_identity(self.finding(), [], {}, migration_type="unknown")


class PrismaIdentityMigrationRequestTests(SimpleTestCase):
    def test_migration_type_defaults_to_deployment_container_name(self):
        serializer = PrismaEngagementIdentityMigrationSerializer(data={})
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual("DeploymentContainerName", serializer.validated_data["migration_type"])
        self.assertTrue(serializer.validated_data["dry_run"])

    def test_validates_migration_type_choices(self):
        for value in ["ID", "DeploymentContainerName"]:
            with self.subTest(value=value):
                serializer = PrismaEngagementIdentityMigrationSerializer(data={"migration_type": value})
                self.assertTrue(serializer.is_valid(), serializer.errors)
                self.assertEqual(value, serializer.validated_data["migration_type"])
        for value in ["unknown", "", None]:
            with self.subTest(value=value):
                serializer = PrismaEngagementIdentityMigrationSerializer(data={"migration_type": value})
                self.assertFalse(serializer.is_valid())
                self.assertIn("migration_type", serializer.errors)

    @override_settings(PROVIDER_CORE_ENGINE="")
    @patch("dojo.api_v2.views.bulk_migrate_prisma_ids_task")
    def test_id_request_queues_selected_type_without_search_engine_configuration(self, task):
        from dojo.api_v2.views import FindingViewSet

        task.apply_async.return_value.id = "migration-task"
        request = SimpleNamespace(data={"migration_type": "ID", "dry_run": False},
                                  user=SimpleNamespace(pk=42))
        response = FindingViewSet().bulk_migrate_prisma_ids(request)
        self.assertEqual(202, response.status_code)
        self.assertEqual("ID", response.data["migration_type"])
        task.apply_async.assert_called_once_with(args=(42, False, 0, 10, None, "ID"))

    @override_settings(PROVIDER_CORE_ENGINE="")
    @patch("dojo.api_v2.views.bulk_migrate_prisma_ids_task")
    def test_deployment_request_still_requires_search_engine_configuration(self, task):
        from dojo.api_v2.views import FindingViewSet

        response = FindingViewSet().bulk_migrate_prisma_ids(
            SimpleNamespace(data={}, user=SimpleNamespace(pk=42)),
        )
        self.assertEqual(503, response.status_code)
        task.apply_async.assert_not_called()

    @patch("dojo.tasks.run_bulk_migration")
    @patch("dojo.tasks.User.objects.get")
    def test_task_forwards_selected_type(self, get_user, migrate):
        from dojo.tasks import bulk_migrate_prisma_ids_task

        bulk_migrate_prisma_ids_task(42, False, migration_type="ID")
        migrate.assert_called_once_with(get_user.return_value, False, after_engagement_id=0,
                                        batch_size=10, engagement_ids=None, migration_type="ID")

    @override_settings(PROVIDER_CORE_ENGINE="")
    @patch("dojo.finding.prisma_images_identity.EngineImageClient")
    @patch("dojo.finding.prisma_images_identity.Engagement.objects.filter")
    @patch("dojo.finding.prisma_images_identity.prisma_images_identity_findings")
    def test_bulk_id_dry_run_prepares_changes_without_engine_or_writes(self, eligible, engagements_filter, client):
        finding = PrismaIdentityTests().finding()
        original_id = finding.unique_id_from_tool
        deployed = prepare_finding_identity(finding, [], {})
        finding.pk = 1
        finding.unique_id_from_tool = deployed["unique_id_from_tool"]
        finding.description = deployed["description"]
        eligible.return_value.filter.return_value.iterator.return_value = [finding]
        engagements = engagements_filter.return_value
        engagements.count.return_value = 1
        engagements.filter.return_value.order_by.return_value.__getitem__.side_effect = [
            [SimpleNamespace(pk=7, name="app")], [],
        ]
        result = run_bulk_migration(SimpleNamespace(pk=42), True, migration_type="ID")
        self.assertEqual(1, result["processed"])
        self.assertEqual(1, result["would_update"])
        self.assertEqual(0, result["updated"])
        self.assertEqual(0, result["errors"])
        self.assertEqual(0, result["skipped"])
        self.assertEqual(deployed["unique_id_from_tool"], finding.unique_id_from_tool)
        self.assertNotEqual(original_id, finding.unique_id_from_tool)
        client.assert_not_called()


@override_settings(PROVIDER_CORE_ENGINE="https://search.example/")
class EngineImageClientTests(SimpleTestCase):
    @patch("dojo.finding.prisma_images_identity.requests.Session")
    def test_runtime_search_uses_engagement_and_image_key(self, session_class):
        response = session_class.return_value.request.return_value
        response.status_code = 200
        response.json.return_value = {"images": ["registry/app:v1"]}
        client = EngineImageClient()
        self.assertEqual(["registry/app:v1"], client.get_runtime("app"))
        session_class.return_value.request.assert_called_once_with(
            "GET", "https://search.example/engine-backend/search/getImagesRuntime",
            timeout=(5, 60), allow_redirects=False, params={"searchKey": "image", "searchValue": "app"},
        )

    @patch("dojo.finding.prisma_images_identity.requests.Session")
    def test_deployments_are_queried_in_batches_and_empty_list_skips_call(self, session_class):
        response = session_class.return_value.request.return_value
        response.status_code = 200
        response.json.return_value = {"deployments": []}
        client = EngineImageClient()
        self.assertEqual({}, client.get_deployments([]))
        session_class.return_value.request.assert_not_called()
        images = [f"registry/app:v{index}" for index in range(501)]
        self.assertEqual({}, client.get_deployments(images))
        calls = session_class.return_value.request.call_args_list
        self.assertEqual([500, 1], [len(call.kwargs["json"]["images"]) for call in calls])

    @patch("dojo.finding.prisma_images_identity.requests.Session")
    def test_network_failure_is_not_interpreted_as_empty_runtime(self, session_class):
        session_class.return_value.request.side_effect = requests.Timeout()
        with self.assertRaises(EngineLookupError):
            EngineImageClient().get_runtime("app")


@override_settings(PROVIDER_CORE_ENGINE="https://search.example/",
                   CELERY_TASK_ALWAYS_EAGER=True, CELERY_TASK_EAGER_PROPAGATES=True)
class PrismaIdentityMigrationApiTests(APITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.client.force_authenticate(User.objects.get(username="admin"))
        self.url = reverse("finding-bulk-migrate-prisma-ids")
        self.finding = Finding.objects.order_by("pk").first()
        Finding.objects.exclude(pk=self.finding.pk).update(active=False)
        ScanTest.objects.filter(pk=self.finding.test_id).update(title="ciclo_escaneo")
        self.engagement = self.finding.test.engagement
        Engagement.objects.filter(pk=self.engagement.pk).update(name="app", description="ITEM: IMAGES\nPROVIDER: PRISMA")
        source = PrismaIdentityTests().finding()
        Finding.objects.filter(pk=self.finding.pk).update(
            active=True, is_mitigated=False, description=source.description,
            impact=source.impact, unique_id_from_tool=source.unique_id_from_tool, mitigation=source.mitigation,
        )
        self.finding.refresh_from_db()
        self.finding.tags = ["prisma", "images"]
        self.finding.save()
        self.old_id = self.finding.unique_id_from_tool

    def configure_client(self, client_class, images=None):
        client_class.return_value.get_runtime.return_value = ["registry/app:v1"] if images is None else images
        client_class.return_value.get_deployments.return_value = {"registry/app:v1": [("deploy-1", "container-1")]}

    @patch("dojo.finding.prisma_images_identity.EngineImageClient")
    def test_default_dry_run_discovers_engagement_without_writing(self, client_class):
        self.configure_client(client_class)
        response = self.client.post(self.url, {}, format="json")
        self.assertEqual(202, response.status_code, response.data)
        self.assertEqual("queued", response.data["status"])
        self.assertTrue(response.data["dry_run"])
        self.finding.refresh_from_db()
        self.assertEqual(self.old_id, self.finding.unique_id_from_tool)
        client_class.return_value.get_runtime.assert_called_once_with("app")

    @patch("dojo.finding.prisma_images_identity.EngineImageClient")
    def test_migrates_active_findings_and_is_idempotent(self, client_class):
        self.configure_client(client_class)
        payload = {"dry_run": False, "engagement_ids": [self.engagement.pk]}
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(202, response.status_code, response.data)
        self.finding.refresh_from_db()
        self.assertEqual("registry/app@deploy-1,container-1," + PrismaIdentityTests.suffix,
                         base64.b64decode(self.finding.unique_id_from_tool).decode())
        self.assertIn("Deployment:</strong> deploy-1", self.finding.description)
        self.assertIn("Container Name:</strong> container-1", self.finding.description)
        self.assertIn("Deployment: deploy-1", self.finding.impact)
        self.assertIn("Container Name: container-1", self.finding.impact)
        migrated_id = self.finding.unique_id_from_tool
        migrated_impact = self.finding.impact
        second = self.client.post(self.url, payload, format="json")
        self.assertEqual(202, second.status_code, second.data)
        self.finding.refresh_from_db()
        self.assertEqual(migrated_id, self.finding.unique_id_from_tool)
        self.assertEqual(migrated_impact, self.finding.impact)

    @patch("dojo.finding.prisma_images_identity.EngineImageClient")
    def test_migrates_deployment_identity_back_to_cloud_id_without_engine(self, client_class):
        self.configure_client(client_class)
        response = self.client.post(self.url, {"dry_run": False}, format="json")
        self.assertEqual(202, response.status_code, response.data)
        self.finding.refresh_from_db()
        self.assertNotEqual(self.old_id, self.finding.unique_id_from_tool)
        client_class.reset_mock()
        with override_settings(PROVIDER_CORE_ENGINE=""):
            response = self.client.post(self.url, {"dry_run": False, "migration_type": "ID"}, format="json")
        self.assertEqual(202, response.status_code, response.data)
        self.assertEqual("ID", response.data["migration_type"])
        self.finding.refresh_from_db()
        self.assertEqual(self.old_id, self.finding.unique_id_from_tool)
        self.assertNotIn("Deployment:", self.finding.description)
        self.assertNotIn("Container Name:", self.finding.description)
        self.assertIn("Keep this note", self.finding.description)
        self.assertNotIn("Deployment:", self.finding.impact)
        self.assertNotIn("Container Name:", self.finding.impact)
        self.assertIn("Image ID: sha256:old", self.finding.impact)
        client_class.assert_not_called()

    @patch("dojo.finding.prisma_images_identity.EngineImageClient")
    def test_updates_impact_even_when_identity_and_description_are_unchanged(self, client_class):
        self.configure_client(client_class)
        values = prepare_finding_identity(self.finding, ["registry/app:v1"], {
            "registry/app:v1": [("deploy-1", "container-1")],
        })
        Finding.objects.filter(pk=self.finding.pk).update(
            unique_id_from_tool=values["unique_id_from_tool"], description=values["description"],
        )
        response = self.client.post(self.url, {"dry_run": False}, format="json")
        self.assertEqual(202, response.status_code, response.data)
        self.finding.refresh_from_db()
        self.assertEqual(values["impact"], self.finding.impact)

    @patch("dojo.finding.prisma_images_identity.EngineImageClient")
    def test_id_migration_cleans_only_impact_and_respects_dry_run(self, client_class):
        old_impact = self.finding.impact + "\nDeployment: old\nContainer Name: old"
        Finding.objects.filter(pk=self.finding.pk).update(impact=old_impact)
        for dry_run in (True, False):
            with self.subTest(dry_run=dry_run):
                response = self.client.post(self.url, {"dry_run": dry_run, "migration_type": "ID"}, format="json")
                self.assertEqual(202, response.status_code, response.data)
                self.finding.refresh_from_db()
                self.assertEqual(self.old_id, self.finding.unique_id_from_tool)
                if dry_run:
                    self.assertEqual(old_impact, self.finding.impact)
                else:
                    self.assertNotIn("Deployment:", self.finding.impact)
                    self.assertNotIn("Container Name:", self.finding.impact)
                    self.assertIn("Image ID: sha256:old", self.finding.impact)
        client_class.assert_not_called()

    def test_impact_changed_during_migration_is_not_overwritten(self):
        Finding.objects.filter(pk=self.finding.pk).update(impact=self.finding.impact + "\nDeployment: old")
        self.finding.refresh_from_db()
        original_description = self.finding.description
        changed_impact = self.finding.impact + "\nKeep concurrent edit"

        def prepare_with_concurrent_edit(finding, *args, **kwargs):
            values = prepare_finding_identity(finding, *args, **kwargs)
            Finding.objects.filter(pk=finding.pk).update(impact=changed_impact)
            return values

        with patch("dojo.finding.prisma_images_identity.prepare_finding_identity",
                   side_effect=prepare_with_concurrent_edit):
            result = migrate_engagement(self.engagement, Finding.objects.filter(pk=self.finding.pk),
                                        None, False, migration_type="ID")
        self.assertEqual(0, result["updated"])
        self.assertEqual([{"id": self.finding.pk, "reason": "Finding changed during migration; retry."}],
                         result["skipped"])
        self.finding.refresh_from_db()
        self.assertEqual(changed_impact, self.finding.impact)
        self.assertEqual(self.old_id, self.finding.unique_id_from_tool)
        self.assertEqual(original_description, self.finding.description)

    @patch("dojo.finding.prisma_images_identity.EngineImageClient")
    def test_no_runtime_images_migrates_to_empty_deployment_fields(self, client_class):
        self.configure_client(client_class, images=[])
        client_class.return_value.get_deployments.return_value = {}
        response = self.client.post(self.url, {"dry_run": False}, format="json")
        self.assertEqual(202, response.status_code, response.data)
        self.finding.refresh_from_db()
        self.assertEqual("registry/app@,," + PrismaIdentityTests.suffix,
                         base64.b64decode(self.finding.unique_id_from_tool).decode())
        client_class.return_value.get_deployments.assert_called_once_with([])

    @patch("dojo.finding.prisma_images_identity.EngineImageClient")
    def test_lookup_error_does_not_change_finding(self, client_class):
        client_class.return_value.get_runtime.side_effect = EngineLookupError("Unavailable")
        response = self.client.post(self.url, {"dry_run": False}, format="json")
        self.assertEqual(202, response.status_code)
        client_class.return_value.get_runtime.assert_called_once_with("app")
        self.finding.refresh_from_db()
        self.assertEqual(self.old_id, self.finding.unique_id_from_tool)

    @patch("dojo.finding.prisma_images_identity.EngineImageClient")
    def test_wrong_item_test_tag_or_inactive_finding_are_excluded(self, client_class):
        for field, value in [("active", False), ("is_mitigated", True)]:
            with self.subTest(field=field):
                Finding.objects.filter(pk=self.finding.pk).update(**{field: value})
                response = self.client.post(self.url, {}, format="json")
                self.assertEqual(202, response.status_code)
                Finding.objects.filter(pk=self.finding.pk).update(active=True, is_mitigated=False)
        Engagement.objects.filter(pk=self.engagement.pk).update(description="ITEM: HOSTS")
        self.assertEqual(202, self.client.post(self.url, {}, format="json").status_code)
        Engagement.objects.filter(pk=self.engagement.pk).update(description="ITEM: ECR")
        ScanTest.objects.filter(pk=self.finding.test_id).update(title="other scan")
        self.assertEqual(202, self.client.post(self.url, {}, format="json").status_code)
        ScanTest.objects.filter(pk=self.finding.test_id).update(title="ciclo escaneo")
        self.finding.tags = ["prisma"]
        self.finding.save()
        self.assertEqual(202, self.client.post(self.url, {}, format="json").status_code)
        client_class.assert_not_called()

    @patch("dojo.api_v2.views.bulk_migrate_prisma_ids_task")
    def test_non_superuser_cannot_queue_migration(self, task):
        user = User.objects.create(username="migration-without-access", is_active=True)
        self.client.force_authenticate(user)
        response = self.client.post(self.url, {"dry_run": False}, format="json")
        self.assertEqual(403, response.status_code, response.data)
        task.apply_async.assert_not_called()

    @patch("dojo.finding.prisma_images_identity.EngineImageClient")
    def test_accepts_ecr_item_and_scan_title_with_spaces(self, client_class):
        self.configure_client(client_class)
        Engagement.objects.filter(pk=self.engagement.pk).update(description="ITEM: ECR\nPROVIDER: PRISMA")
        ScanTest.objects.filter(pk=self.finding.test_id).update(title="Ciclo Escaneo")
        response = self.client.post(self.url, {}, format="json")
        self.assertEqual(202, response.status_code, response.data)
        client_class.return_value.get_runtime.assert_called_once_with("app")

    @patch("dojo.finding.prisma_images_identity.EngineImageClient")
    def test_processes_every_engagement_in_batches_without_reprocessing(self, client_class):
        self.configure_client(client_class)
        other = Finding.objects.exclude(test__engagement_id=self.engagement.pk).order_by("pk").first()
        self.assertIsNotNone(other)
        ScanTest.objects.filter(pk=other.test_id).update(title="ciclo_escaneo")
        Engagement.objects.filter(pk=other.test.engagement_id).update(description="ITEM: ECR")
        Finding.objects.filter(pk=other.pk).update(
            active=True, is_mitigated=False, unique_id_from_tool=self.old_id,
            description=self.finding.description, impact=self.finding.impact, mitigation=self.finding.mitigation,
        )
        other.refresh_from_db()
        other.tags = ["prisma", "images"]
        other.save()
        response = self.client.post(self.url, {"limit": 1}, format="json")
        self.assertEqual(202, response.status_code, response.data)
        processed = sorted(call.args[0] for call in client_class.return_value.get_runtime.call_args_list)
        self.engagement.refresh_from_db()
        self.assertEqual(sorted([self.engagement.name, other.test.engagement.name]), processed)

    def test_requires_authentication_and_valid_limits(self):
        response = self.client.post(self.url, {"limit": 51}, format="json")
        self.assertEqual(400, response.status_code)
        self.assertIn(APIClient().post(self.url, {}, format="json").status_code, [401, 403])
