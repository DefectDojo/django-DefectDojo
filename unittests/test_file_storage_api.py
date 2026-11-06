"""
Uploaded files are read and written through Django's storage API.

Every test here runs with an in-memory storage backend that has no local filesystem
path (``storage.path()`` raises ``NotImplementedError``, as it does for remote
backends), so code that reads ``FieldFile.path`` or builds a path from ``MEDIA_ROOT``
fails these tests instead of passing by accident on disk.
"""
import datetime
import os
from unittest import mock

from django.conf import settings
from django.core.files.base import ContentFile
from django.core.files.storage import InMemoryStorage, default_storage
from django.core.files.uploadedfile import SimpleUploadedFile
from django.http import FileResponse, Http404
from django.test import Client, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.jira import helper as jira_helper
from dojo.models import (
    Dojo_User,
    Engagement,
    FileUpload,
    Finding,
    Product,
    Product_Type,
    Risk_Acceptance,
    Test,
    Test_Type,
)
from dojo.utils import generate_file_response

from .dojo_test_case import DojoTestCase


class NoLocalPathStorage(InMemoryStorage):

    """In-memory storage that, like a remote backend, cannot hand out a local path."""

    def path(self, name):
        msg = "This backend has no local filesystem path."
        raise NotImplementedError(msg)

    def _relative_path(self, name):
        # InMemoryStorage resolves its own tree through path(); keep that internal use working.
        return os.path.relpath(InMemoryStorage.path(self, name), self.location)


IN_MEMORY_STORAGES = {
    **settings.STORAGES,
    "default": {"BACKEND": f"{__name__}.NoLocalPathStorage"},
}


def _read_streaming(response) -> bytes:
    """Read a (streaming) file response without closing it through Django's signal path."""
    content = b"".join(response.streaming_content)
    # response.close() would send request_finished, whose close_old_connections handler
    # closes this TestCase's DB connection; close the underlying handle directly instead.
    if getattr(response, "file_to_stream", None) is not None:
        response.file_to_stream.close()
    return content


@override_settings(STORAGES=IN_MEMORY_STORAGES)
class TestFileUploadStorageLifecycle(DojoTestCase):

    def _make_file_upload(self, content=b"finding evidence content") -> FileUpload:
        return FileUpload.objects.create(
            title="evidence",
            file=SimpleUploadedFile("evidence.txt", content),
        )

    def test_backend_has_no_local_path(self):
        # Precondition for every other test in this module.
        with self.assertRaises(NotImplementedError):
            default_storage.path("anything.txt")

    def test_upload_is_written_to_storage(self):
        upload = self._make_file_upload()
        self.assertTrue(default_storage.exists(upload.file.name))
        with default_storage.open(upload.file.name, "rb") as handle:
            self.assertEqual(b"finding evidence content", handle.read())

    def test_delete_removes_file_from_storage(self):
        upload = self._make_file_upload()
        name = upload.file.name

        upload.delete()

        self.assertFalse(default_storage.exists(name))

    def test_queryset_delete_removes_file_from_storage(self):
        # Bulk deletes skip FileUpload.delete(); the post_delete signal is the cleanup path.
        upload = self._make_file_upload()
        name = upload.file.name

        FileUpload.objects.filter(pk=upload.pk).delete()

        self.assertFalse(default_storage.exists(name))

    def test_delete_tolerates_file_already_gone(self):
        upload = self._make_file_upload()
        default_storage.delete(upload.file.name)

        upload.delete()

        self.assertFalse(FileUpload.objects.filter(pk=upload.pk).exists())

    def test_replacing_the_file_removes_the_old_one(self):
        upload = self._make_file_upload()
        old_name = upload.file.name

        upload.file = SimpleUploadedFile("replacement.txt", b"new content")
        upload.save()

        self.assertFalse(default_storage.exists(old_name))
        self.assertTrue(default_storage.exists(upload.file.name))
        self.assertNotEqual(old_name, upload.file.name)

    def test_saving_without_changing_the_file_keeps_it(self):
        upload = self._make_file_upload()

        upload.title = "renamed"
        upload.save()

        self.assertTrue(default_storage.exists(upload.file.name))

    def test_copy_reads_through_storage(self):
        upload = self._make_file_upload(b"copy me")

        clone = upload.copy()

        self.assertNotEqual(upload.file.name, clone.file.name)
        with default_storage.open(clone.file.name, "rb") as handle:
            self.assertEqual(b"copy me", handle.read())

    def test_generate_file_response_streams_from_storage(self):
        upload = self._make_file_upload(b"0123456789")

        response = generate_file_response(upload)

        self.assertIsInstance(response, FileResponse)
        self.assertEqual("10", response["Content-Length"])
        self.assertEqual('attachment; filename="evidence.txt"', response["Content-Disposition"])
        self.assertEqual("text/plain", response["Content-Type"])
        self.assertEqual(b"0123456789", _read_streaming(response))

    def test_generate_file_response_missing_from_storage_is_404(self):
        upload = self._make_file_upload()
        default_storage.delete(upload.file.name)

        with self.assertRaises(Http404):
            generate_file_response(upload)


@override_settings(STORAGES=IN_MEMORY_STORAGES)
class TestDownloadsThroughStorage(DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        cls.product_type = Product_Type.objects.create(name="Storage API PT")
        cls.product = Product.objects.create(
            name="Storage API Product", description="Test", prod_type=cls.product_type,
        )
        cls.member = Dojo_User.objects.create_user(
            username="storage_api_member", password="testTEST1234!@#$", is_active=True,  # noqa: S106
        )
        cls.outsider = Dojo_User.objects.create_user(
            username="storage_api_outsider", password="testTEST1234!@#$", is_active=True,  # noqa: S106
        )
        cls.superuser = Dojo_User.objects.create_user(
            username="storage_api_superuser", password="testTEST1234!@#$", is_active=True,  # noqa: S106
            is_superuser=True, is_staff=True,
        )
        cls.product.authorized_users.add(cls.member)
        cls.engagement = Engagement.objects.create(
            name="Storage API Engagement",
            product=cls.product,
            target_start=datetime.date(2024, 1, 1),
            target_end=datetime.date(2024, 12, 31),
        )
        test_type, _ = Test_Type.objects.get_or_create(name="Manual Code Review")
        cls.test = Test.objects.create(
            engagement=cls.engagement,
            test_type=test_type,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        cls.finding = Finding.objects.create(
            title="Storage API Finding",
            test=cls.test,
            severity="High",
            numerical_severity="S1",
            reporter=cls.member,
        )
        cls.risk_acceptance = Risk_Acceptance.objects.create(name="Storage API RA", owner=cls.member)
        cls.risk_acceptance.accepted_findings.add(cls.finding)
        cls.engagement.risk_acceptance.add(cls.risk_acceptance)

    def setUp(self):
        super().setUp()
        # setUpTestData objects are shared across tests, but the in-memory storage is
        # per override, so (re)attach fresh files for each test.
        self.upload = FileUpload.objects.create(
            title="evidence", file=SimpleUploadedFile("evidence.txt", b"engagement evidence"),
        )
        self.engagement.files.add(self.upload)
        self.risk_acceptance.path.save("proof.pdf", ContentFile(b"%PDF-1.4 proof"), save=True)

    def _ui_client(self, user):
        client = Client()
        client.force_login(user)
        return client

    def _api_client(self, user):
        token, _ = Token.objects.get_or_create(user=user)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        return client

    # protected_serve: /media/<name>

    def test_protected_serve_member_gets_file_from_storage(self):
        response = self._ui_client(self.member).get(f"{settings.MEDIA_URL}{self.upload.file.name}")

        self.assertEqual(200, response.status_code)
        self.assertEqual(b"engagement evidence", _read_streaming(response))

    def _assert_permission_denied(self, response):
        # PermissionDenied is rendered by the custom handler403 (dojo.views.custom_unauthorized_view),
        # which serves 403.html with status 400.
        self.assertEqual(400, response.status_code)
        self.assertTemplateUsed(response, "403.html")
        self.assertNotIn(b"engagement evidence", response.content)

    def test_protected_serve_without_view_permission_is_denied(self):
        response = self._ui_client(self.outsider).get(f"{settings.MEDIA_URL}{self.upload.file.name}")

        self._assert_permission_denied(response)

    def test_protected_serve_missing_from_storage_is_404(self):
        default_storage.delete(self.upload.file.name)

        response = self._ui_client(self.member).get(f"{settings.MEDIA_URL}{self.upload.file.name}")

        self.assertEqual(404, response.status_code)

    # access_file

    def test_access_file_member_gets_file_from_storage(self):
        url = reverse("access_file", args=(self.upload.id, self.engagement.id, "Engagement"))

        response = self._ui_client(self.member).get(url)

        self.assertEqual(200, response.status_code)
        self.assertEqual(b"engagement evidence", _read_streaming(response))

    def test_access_file_without_view_permission_is_denied(self):
        url = reverse("access_file", args=(self.upload.id, self.engagement.id, "Engagement"))

        response = self._ui_client(self.outsider).get(url)

        self._assert_permission_denied(response)

    # manage_files: deleting a file through the formset removes it from storage

    def test_manage_files_delete_removes_file_from_storage(self):
        name = self.upload.file.name
        data = {
            "form-TOTAL_FORMS": "1",
            "form-INITIAL_FORMS": "1",
            "form-MIN_NUM_FORMS": "0",
            "form-MAX_NUM_FORMS": "1000",
            "form-0-id": str(self.upload.id),
            "form-0-title": self.upload.title,
            "form-0-DELETE": "on",
        }
        response = self._ui_client(self.superuser).post(
            reverse("manage_files", args=(self.engagement.id, "Engagement")), data,
        )

        self.assertEqual(302, response.status_code, getattr(response, "content", b"")[:500])
        self.assertFalse(FileUpload.objects.filter(pk=self.upload.pk).exists())
        self.assertFalse(default_storage.exists(name))

    # Risk acceptance proof: UI download

    def test_download_risk_acceptance_reads_from_storage(self):
        url = reverse("download_risk_acceptance", args=(self.engagement.id, self.risk_acceptance.id))

        response = self._ui_client(self.member).get(url)

        self.assertEqual(200, response.status_code)
        self.assertEqual("application/pdf", response["Content-Type"])
        self.assertEqual(b"%PDF-1.4 proof", b"".join(response.streaming_content))

    def test_download_risk_acceptance_missing_from_storage_is_404(self):
        default_storage.delete(self.risk_acceptance.path.name)
        url = reverse("download_risk_acceptance", args=(self.engagement.id, self.risk_acceptance.id))

        response = self._ui_client(self.member).get(url)

        self.assertEqual(404, response.status_code)

    # Risk acceptance proof: API download

    def test_api_download_proof_reads_from_storage(self):
        url = reverse("risk_acceptance-download-proof", args=(self.risk_acceptance.id,))

        response = self._api_client(self.member).get(url)

        self.assertEqual(200, response.status_code)
        self.assertEqual("application/pdf", response["Content-Type"])
        self.assertEqual(str(len(b"%PDF-1.4 proof")), response["Content-Length"])
        self.assertEqual(b"%PDF-1.4 proof", _read_streaming(response))

    def test_api_download_proof_without_permission_is_hidden(self):
        url = reverse("risk_acceptance-download-proof", args=(self.risk_acceptance.id,))

        response = self._api_client(self.outsider).get(url)

        self.assertEqual(404, response.status_code)


@override_settings(STORAGES=IN_MEMORY_STORAGES)
class TestJiraAttachmentThroughStorage(DojoTestCase):

    def test_jira_attachment_uploads_bytes_from_storage(self):
        upload = FileUpload.objects.create(
            title="screenshot", file=SimpleUploadedFile("screenshot.png", b"\x89PNG fake"),
        )
        jira = mock.Mock()
        issue = mock.Mock()
        issue.fields.attachment = []
        uploaded = {}

        def add_attachment(issue, attachment, filename):
            uploaded["filename"] = filename
            uploaded["content"] = attachment.read()

        jira.add_attachment.side_effect = add_attachment

        result = jira_helper.jira_attachment(mock.Mock(), jira, issue, upload.file)

        self.assertTrue(result)
        self.assertEqual(upload.file.name.rsplit("/", 1)[-1], uploaded["filename"])
        self.assertEqual(b"\x89PNG fake", uploaded["content"])

    def test_jira_attachment_skips_file_already_on_issue(self):
        upload = FileUpload.objects.create(
            title="screenshot", file=SimpleUploadedFile("screenshot.png", b"\x89PNG fake"),
        )
        jira = mock.Mock()
        issue = mock.Mock()
        existing = mock.Mock()
        existing.filename = upload.file.name.rsplit("/", 1)[-1]
        issue.fields.attachment = [existing]

        result = jira_helper.jira_attachment(mock.Mock(), jira, issue, upload.file)

        self.assertIsNone(result)
        jira.add_attachment.assert_not_called()
