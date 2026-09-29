"""
Regression tests for scan-import permission checks under upload limits.

The import/reimport permission classes parse ``request.data`` inside their
``has_permission`` to resolve the target product/engagement/test before the
serializer runs. A very large scan import (many form fields) makes Django's
multipart parser raise ``TooManyFieldsSent`` (a ``SuspiciousOperation``) while
``request.data`` is evaluated. That exception used to escape the permission
check as an opaque error and generate on-call noise; it must instead surface as
a clean DRF ``ValidationError`` (HTTP 400) with an actionable message.

The limit itself (``DATA_UPLOAD_MAX_NUMBER_FIELDS``) is now configurable via the
``DD_DATA_UPLOAD_MAX_NUMBER_FIELDS`` environment variable so operators can raise
it for instances that legitimately submit very large imports.
"""
from django.conf import settings
from django.core.exceptions import TooManyFieldsSent
from django.test import SimpleTestCase, override_settings
from rest_framework.exceptions import ValidationError
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from dojo.authorization.api_permissions import (
    UserHasImportPermission,
    UserHasMetaImportPermission,
    UserHasReimportPermission,
)

IMPORT_PERMISSION_CLASSES = (
    UserHasImportPermission,
    UserHasMetaImportPermission,
    UserHasReimportPermission,
)


class ImportPermissionUploadLimitsTest(SimpleTestCase):
    def _multipart_request(self, field_count: int) -> Request:
        payload = {f"field_{i}": "x" for i in range(field_count)}
        django_request = APIRequestFactory().post(
            "/api/v2/import-scan/", payload, format="multipart",
        )
        return Request(django_request, parsers=[MultiPartParser(), FormParser()])

    @override_settings(DATA_UPLOAD_MAX_NUMBER_FIELDS=5)
    def test_too_many_fields_raises_validation_error(self):
        # Without the fix Django's TooManyFieldsSent escapes the permission check;
        # with the fix each import/reimport permission raises a DRF ValidationError.
        for permission_class in IMPORT_PERMISSION_CLASSES:
            with self.subTest(permission=permission_class.__name__):
                request = self._multipart_request(field_count=20)
                with self.assertRaises(ValidationError) as ctx:
                    permission_class().has_permission(request, view=None)
                self.assertIn("upload limits", str(ctx.exception).lower())

    @override_settings(DATA_UPLOAD_MAX_NUMBER_FIELDS=5)
    def test_request_within_limit_parses_without_size_error(self):
        # A request under the limit parses normally (no SuspiciousOperation).
        request = self._multipart_request(field_count=3)
        try:
            parsed = request.data
        except TooManyFieldsSent:  # pragma: no cover - would mean the guard misfired
            self.fail("request under the field limit must not raise TooManyFieldsSent")
        self.assertEqual(sorted(parsed.keys()), ["field_0", "field_1", "field_2"])


class DataUploadMaxNumberFieldsSettingTest(SimpleTestCase):
    def test_default_value(self):
        # Default preserved while the value is now sourced from the environment.
        self.assertEqual(settings.DATA_UPLOAD_MAX_NUMBER_FIELDS, 10240)
