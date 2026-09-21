from pathlib import Path

from django.core.files.uploadedfile import SimpleUploadedFile
from django.http import FileResponse, Http404
from parameterized import parameterized

from dojo.models import FileUpload
from dojo.utils import generate_file_response, generate_file_response_from_file_path

from .dojo_test_case import DojoTestCase


class TestGenerateFileResponse(DojoTestCase):

    """
    Regression: downloading an uploaded file whose DB row exists but whose bytes are
    missing on disk raised a low-level FileNotFoundError that surfaced as an HTTP 500
    (e.g. GET /access_file/<id>/<oid>/Finding). A missing file must return a clean 404.
    """

    def _make_file_upload(self) -> FileUpload:
        return FileUpload.objects.create(
            title="evidence",
            file=SimpleUploadedFile("evidence.txt", b"finding evidence content"),
        )

    @parameterized.expand([(True,), (False,)])
    def test_generate_file_response_missing_file_returns_404(self, file_on_disk):
        file_object = self._make_file_upload()
        disk_path = file_object.file.path
        if not file_on_disk:
            Path(disk_path).unlink()

        if file_on_disk:
            response = generate_file_response(file_object)
            self.assertIsInstance(
                response,
                FileResponse,
                msg=f"expected FileResponse when the file exists at {disk_path}",
            )
            # Close the underlying file handle directly. response.close() would emit
            # Django's request_finished signal, whose close_old_connections handler closes
            # this TestCase's DB connection and breaks the remaining tests in the class.
            response.file_to_stream.close()
        else:
            # Previously raised FileNotFoundError -> HTTP 500; must now be Http404.
            with self.assertRaises(
                Http404,
                msg=f"expected Http404 when the file is missing at {disk_path}",
            ):
                generate_file_response(file_object)

    @parameterized.expand([(True,), (False,)])
    def test_generate_file_response_from_file_path_missing_file_returns_404(self, file_on_disk):
        file_object = self._make_file_upload()
        disk_path = file_object.file.path
        if not file_on_disk:
            Path(disk_path).unlink()

        if file_on_disk:
            response = generate_file_response_from_file_path(disk_path)
            self.assertIsInstance(
                response,
                FileResponse,
                msg=f"expected FileResponse when the file exists at {disk_path}",
            )
            # Close the underlying file handle directly. response.close() would emit
            # Django's request_finished signal, whose close_old_connections handler closes
            # this TestCase's DB connection and breaks the remaining tests in the class.
            response.file_to_stream.close()
        else:
            self.assertFalse(
                Path(disk_path).is_file(),
                msg=f"precondition: file should be absent at {disk_path}",
            )
            with self.assertRaises(
                Http404,
                msg=f"expected Http404 when the file is missing at {disk_path}",
            ):
                generate_file_response_from_file_path(disk_path)
