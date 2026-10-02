import base64
import logging

from django.utils import timezone

from dojo.file_uploads.models import FileUpload
from dojo.importers.base_importer import BaseImporter
from dojo.models import (
    Development_Environment,
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
    User,
)

from .dojo_test_case import DojoTestCase

logger = logging.getLogger(__name__)


class TestFileUploadTitleNotUnique(DojoTestCase):

    """
    A FileUpload belongs to the Engagement/Test/Finding it is attached to, so the
    same file name has to be usable in more than one of them. `title` used to be
    declared `unique=True`, which made it unique across the whole instance. See
    #12507.
    """

    def test_same_title_can_be_used_more_than_once(self):
        first = FileUpload.objects.create(title="Report")
        second = FileUpload.objects.create(title="Report")
        self.assertNotEqual(first.pk, second.pk)
        self.assertEqual(2, FileUpload.objects.filter(title="Report").count())

    def test_title_field_is_not_declared_unique(self):
        self.assertFalse(FileUpload._meta.get_field("title").unique)


class TestImporterProcessFiles(DojoTestCase):

    """
    `process_files` matched an existing FileUpload on title alone, so a parser
    supplying an attachment whose name was already in use anywhere on the
    instance reused that row and then overwrote its content — including rows
    belonging to a finding in an unrelated product.
    """

    def _make_test(self, product_name):
        product_type, _ = Product_Type.objects.get_or_create(name="file-uploads")
        product, _ = Product.objects.get_or_create(
            name=product_name, description="Test", prod_type=product_type,
        )
        engagement, _ = Engagement.objects.get_or_create(
            name=f"{product_name} engagement",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        test_type, _ = Test_Type.objects.get_or_create(name="Generic Findings Import")
        environment, _ = Development_Environment.objects.get_or_create(name="Development")
        return Test.objects.create(
            engagement=engagement,
            test_type=test_type,
            environment=environment,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )

    def _finding_with_unsaved_file(self, test, title, payload):
        reporter, _ = User.objects.get_or_create(username="file-uploads-reporter")
        finding = Finding.objects.create(
            title=f"finding carrying {payload.decode()}",
            test=test,
            severity="High",
            reporter=reporter,
        )
        finding.unsaved_files = [{
            "title": title,
            "data": base64.b64encode(payload).decode(),
        }]
        return finding

    def test_same_attachment_name_in_two_products_keeps_both_contents(self):
        importer = BaseImporter.__new__(BaseImporter)
        first = self._finding_with_unsaved_file(
            self._make_test("file-uploads-product-a"), "evidence.txt", b"first",
        )
        second = self._finding_with_unsaved_file(
            self._make_test("file-uploads-product-b"), "evidence.txt", b"second",
        )

        importer.process_files(first)
        importer.process_files(second)

        first_upload = first.files.get()
        second_upload = second.files.get()
        self.assertNotEqual(
            first_upload.pk, second_upload.pk,
            "findings in two products were attached to the same FileUpload row",
        )
        # Each finding must still serve the bytes it was imported with.
        try:
            with first_upload.file.open("rb") as handle:
                self.assertEqual(b"first", handle.read())
            with second_upload.file.open("rb") as handle:
                self.assertEqual(b"second", handle.read())
        finally:
            first_upload.delete()
            second_upload.delete()
