"""
Regression: an API write whose row was deleted while the request ran answered 500.

``Finding.save()`` forces the UPDATE of a finding that is already saved, so a finding deleted while
a request is writing it raises Django's forced-update ``DatabaseError`` instead of being re-inserted.
``perform_update`` answers that with 404, but the other writes that end in a model save (the
finding ``close`` and ``verify`` actions, and anything else calling the shared save helpers)
answered a bare 500. ``custom_exception_handler`` now answers every such miss with 404, the status
of a request to an object that does not exist.

Only the exact miss Django raises (a bare ``DatabaseError`` saying no row was affected) qualifies:
every genuine database failure is a ``DatabaseError`` subclass and keeps its 500.
"""
from unittest.mock import MagicMock, patch

from django.db import DatabaseError
from django.db.utils import IntegrityError, OperationalError
from django.test import SimpleTestCase

from dojo.api_v2.exception_handler import VANISHED_ROW_RESPONSE_MESSAGE, custom_exception_handler


class VanishedRowExceptionHandlerTest(SimpleTestCase):

    def test_forced_update_miss_returns_404(self):
        response = custom_exception_handler(DatabaseError("Forced update did not affect any rows."), {})

        self.assertEqual(response.status_code, 404, msg=response.data)
        self.assertEqual(response.data, {"message": VANISHED_ROW_RESPONSE_MESSAGE})

    def test_update_fields_miss_returns_404(self):
        response = custom_exception_handler(DatabaseError("Save with update_fields did not affect any rows."), {})

        self.assertEqual(response.status_code, 404, msg=response.data)

    def test_database_error_subclass_with_the_same_words_keeps_its_500(self):
        settings = MagicMock(api_expose_error_details=False)
        for exc_class in (IntegrityError, OperationalError):
            with self.subTest(exc_class=exc_class.__name__), patch("dojo.api_v2.exception_handler.System_Settings.objects.get", return_value=settings):
                response = custom_exception_handler(exc_class("did not affect any rows"), {})
                self.assertEqual(response.status_code, 500, msg=response.data)

    def test_other_bare_database_error_keeps_its_500(self):
        settings = MagicMock(api_expose_error_details=False)
        with patch("dojo.api_v2.exception_handler.System_Settings.objects.get", return_value=settings):
            response = custom_exception_handler(DatabaseError("server closed the connection unexpectedly"), {})

        self.assertEqual(response.status_code, 500, msg=response.data)
