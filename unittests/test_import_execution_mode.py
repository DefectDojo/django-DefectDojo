from unittest.mock import patch

from django.test import override_settings

from dojo.importers.default_importer import DefaultImporter
from dojo.models import (
    DEDUPLICATION_EXECUTION_MODE_ASYNC,
    DEDUPLICATION_EXECUTION_MODE_ASYNC_WAIT,
    DEDUPLICATION_EXECUTION_MODE_SYNC,
    Development_Environment,
    Dojo_User,
    Engagement,
    Finding,
    Test,
    UserContactInfo,
)

from .dojo_test_case import DojoAPITestCase, DojoTestCase, get_unit_tests_path, versioned_fixtures


@versioned_fixtures
class ImportExecutionModeResolverTest(DojoTestCase):

    """resolve_deduplication_execution_mode: request override > profile > default."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.user = Dojo_User.objects.get(username="admin")
        UserContactInfo.objects.filter(user=self.user).delete()

    def _set_profile(self, *, mode=None):
        UserContactInfo.objects.update_or_create(
            user=self.user,
            defaults={"deduplication_execution_mode": mode},
        )
        self.user.refresh_from_db()

    def test_default_is_async(self):
        self.assertEqual(DEDUPLICATION_EXECUTION_MODE_ASYNC, Dojo_User.resolve_deduplication_execution_mode(self.user))

    def test_request_override_wins_over_profile(self):
        self._set_profile(mode=DEDUPLICATION_EXECUTION_MODE_SYNC)
        self.assertEqual(
            DEDUPLICATION_EXECUTION_MODE_ASYNC_WAIT,
            Dojo_User.resolve_deduplication_execution_mode(self.user, DEDUPLICATION_EXECUTION_MODE_ASYNC_WAIT),
        )

    def test_profile_mode_used_when_no_override(self):
        self._set_profile(mode=DEDUPLICATION_EXECUTION_MODE_ASYNC_WAIT)
        self.assertEqual(DEDUPLICATION_EXECUTION_MODE_ASYNC_WAIT, Dojo_User.resolve_deduplication_execution_mode(self.user))

    def test_empty_profile_falls_back_to_async(self):
        self._set_profile(mode=None)
        self.assertEqual(DEDUPLICATION_EXECUTION_MODE_ASYNC, Dojo_User.resolve_deduplication_execution_mode(self.user))

    def test_invalid_override_ignored(self):
        self.assertEqual(DEDUPLICATION_EXECUTION_MODE_ASYNC, Dojo_User.resolve_deduplication_execution_mode(self.user, "garbage"))

    def test_no_user(self):
        self.assertEqual(DEDUPLICATION_EXECUTION_MODE_ASYNC, Dojo_User.resolve_deduplication_execution_mode(None))

    def test_block_execution_falls_back_to_sync(self):
        # legacy global block_execution flag implies synchronous deduplication
        UserContactInfo.objects.update_or_create(user=self.user, defaults={"block_execution": True})
        self.user.refresh_from_db()
        self.assertEqual(DEDUPLICATION_EXECUTION_MODE_SYNC, Dojo_User.resolve_deduplication_execution_mode(self.user))

    def test_mode_takes_precedence_over_block_execution(self):
        UserContactInfo.objects.update_or_create(
            user=self.user,
            defaults={"block_execution": True, "deduplication_execution_mode": DEDUPLICATION_EXECUTION_MODE_ASYNC_WAIT},
        )
        self.user.refresh_from_db()
        self.assertEqual(DEDUPLICATION_EXECUTION_MODE_ASYNC_WAIT, Dojo_User.resolve_deduplication_execution_mode(self.user))

    def test_wants_block_execution_reads_block_execution_not_mode(self):
        # wants_block_execution is the global switch and is independent of the dedup mode
        UserContactInfo.objects.update_or_create(user=self.user, defaults={"block_execution": True})
        self.user.refresh_from_db()
        self.assertTrue(Dojo_User.wants_block_execution(self.user))
        UserContactInfo.objects.update_or_create(
            user=self.user,
            defaults={"block_execution": False, "deduplication_execution_mode": DEDUPLICATION_EXECUTION_MODE_SYNC},
        )
        self.user.refresh_from_db()
        # a 'sync' dedup mode alone does NOT force global foreground execution
        self.assertFalse(Dojo_User.wants_block_execution(self.user))


@versioned_fixtures
class ImporterDispatchKwargsTest(DojoTestCase):

    """deduplication_execution_mode -> dojo_dispatch_task force flags."""

    fixtures = ["dojo_testdata.json"]

    def _importer(self, mode, **extra):
        return DefaultImporter(
            scan_type="ZAP Scan",
            engagement=Engagement.objects.first(),
            environment=Development_Environment.objects.first(),
            deduplication_execution_mode=mode,
            **extra,
        )

    def test_sync_mode_forces_sync(self):
        self.assertEqual({"force_sync": True}, self._importer(DEDUPLICATION_EXECUTION_MODE_SYNC).post_processing_dispatch_kwargs())

    def test_async_wait_mode_forces_async(self):
        self.assertEqual({"force_async": True}, self._importer(DEDUPLICATION_EXECUTION_MODE_ASYNC_WAIT).post_processing_dispatch_kwargs())

    def test_async_mode_preserves_external_force_sync(self):
        importer = self._importer(DEDUPLICATION_EXECUTION_MODE_ASYNC)
        self.assertEqual({"force_sync": False}, importer.post_processing_dispatch_kwargs())
        self.assertEqual({"force_sync": True}, importer.post_processing_dispatch_kwargs(force_sync=True))

    def test_invalid_mode_defaults_to_async(self):
        self.assertEqual(DEDUPLICATION_EXECUTION_MODE_ASYNC, self._importer("nonsense").deduplication_execution_mode)

    def test_external_force_sync_promotes_to_sync_mode(self):
        importer = self._importer(DEDUPLICATION_EXECUTION_MODE_ASYNC, force_sync=True)
        self.assertEqual(DEDUPLICATION_EXECUTION_MODE_SYNC, importer.deduplication_execution_mode)


@versioned_fixtures
@override_settings(CELERY_TASK_ALWAYS_EAGER=True)
class ImportExecutionModeAPITest(DojoAPITestCase):

    """
    End-to-end: the import endpoints accept and honor deduplication_execution_mode.

    CELERY_TASK_ALWAYS_EAGER runs dispatched tasks inline against the test DB, so
    'async_wait' can actually join its deduplication batch (a real broker/worker
    runs against a different DB and could never see the test transaction's data).
    """

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.login_as_admin()

    def _payload(self, mode):
        return {
            "minimum_severity": "Low",
            "scan_type": "ZAP Scan",
            "engagement": 1,
            "deduplication_execution_mode": mode,
        }

    def test_import_async_wait_returns_statistics(self):
        with (get_unit_tests_path() / "scans/zap/0_zap_sample.xml").open(encoding="utf-8") as testfile:
            payload = self._payload(DEDUPLICATION_EXECUTION_MODE_ASYNC_WAIT)
            payload["file"] = testfile
            result = self.import_scan(payload, 201)
        self.assertIn("statistics", result)
        self.assertIn("after", result["statistics"])
        # async_wait joins deduplication, so it must report completion
        self.assertTrue(result["deduplication_complete"])

    def test_import_async_does_not_await_deduplication(self):
        with (get_unit_tests_path() / "scans/zap/0_zap_sample.xml").open(encoding="utf-8") as testfile:
            payload = self._payload(DEDUPLICATION_EXECUTION_MODE_ASYNC)
            payload["file"] = testfile
            result = self.import_scan(payload, 201)
        self.assertFalse(result["deduplication_complete"])

    def test_import_rejects_invalid_mode(self):
        with (get_unit_tests_path() / "scans/zap/0_zap_sample.xml").open(encoding="utf-8") as testfile:
            payload = self._payload("not-a-mode")
            payload["file"] = testfile
            self.import_scan(payload, 400)


@versioned_fixtures
class NotificationDeduplicationRefreshTest(DojoTestCase):

    """notify_scan_added refreshes duplicate status from the DB once dedup is complete."""

    fixtures = ["dojo_testdata.json"]

    def _importer(self):
        test = Test.objects.first()
        importer = DefaultImporter(
            scan_type="ZAP Scan",
            engagement=test.engagement,
            environment=Development_Environment.objects.first(),
        )
        return importer, test

    @patch("dojo.importers.base_importer.create_notification")
    def test_deduplicated_new_findings_excluded_when_complete(self, mock_notify):
        importer, test = self._importer()
        importer.deduplication_complete = True

        real = Finding(test=test, title="real finding", severity="High")
        real.save()
        dupe = Finding(test=test, title="dupe finding", severity="High")
        dupe.save()
        # Simulate background deduplication having flagged the second finding.
        Finding.objects.filter(pk=dupe.pk).update(duplicate=True)

        importer.notify_scan_added(test, updated_count=2, new_findings=[real, dupe])

        kwargs = mock_notify.call_args.kwargs
        self.assertEqual([f.id for f in kwargs["findings_new"]], [real.id])
        self.assertEqual([f.id for f in kwargs["findings_new_duplicate"]], [dupe.id])
        # headline count excludes the deduplicated finding
        self.assertEqual(kwargs["finding_count"], 1)
        self.assertEqual(kwargs["event"], "scan_added")

    @patch("dojo.importers.base_importer.create_notification")
    def test_async_mode_does_not_refresh(self, mock_notify):
        importer, test = self._importer()
        importer.deduplication_complete = False  # plain async: dedup not awaited

        dupe = Finding(test=test, title="async dupe", severity="High")
        dupe.save()
        Finding.objects.filter(pk=dupe.pk).update(duplicate=True)

        importer.notify_scan_added(test, updated_count=1, new_findings=[dupe])

        kwargs = mock_notify.call_args.kwargs
        # historical behavior: duplicate still listed/counted as new
        self.assertEqual([f.id for f in kwargs["findings_new"]], [dupe.id])
        self.assertEqual(kwargs["findings_new_duplicate"], [])
        self.assertEqual(kwargs["finding_count"], 1)

    @patch("dojo.importers.base_importer.create_notification")
    def test_all_new_findings_duplicate_yields_empty_event(self, mock_notify):
        importer, test = self._importer()
        importer.deduplication_complete = True

        dupe = Finding(test=test, title="only dupe", severity="Low")
        dupe.save()
        Finding.objects.filter(pk=dupe.pk).update(duplicate=True)

        importer.notify_scan_added(test, updated_count=1, new_findings=[dupe])

        kwargs = mock_notify.call_args.kwargs
        self.assertEqual(kwargs["findings_new"], [])
        self.assertEqual([f.id for f in kwargs["findings_new_duplicate"]], [dupe.id])
        self.assertEqual(kwargs["finding_count"], 0)
        # net-new is zero -> empty scan notification
        self.assertEqual(kwargs["event"], "scan_added_empty")
