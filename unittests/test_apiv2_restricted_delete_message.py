"""
Regression tests: a v2 delete blocked by dependent rows answers a sentence, not a tuple repr.

``custom_exception_handler`` answered a ``RestrictedError`` with ``409 {"message": str(exc)}``. ``str()`` of
that exception is a tuple repr naming every referencing row (``("Cannot delete some instances of model ...",
{<Finding: ...>, ...})``), which can be very long. The 409 now says how many records still refer to the row and
which kinds of record they are, so a caller knows what to reassign, without naming any of them.
"""

from django.db.models.deletion import RestrictedError
from django.test import SimpleTestCase

from dojo.api_v2.exception_handler import custom_exception_handler
from dojo.models import Finding, Product


class RestrictedDeleteMessageTest(SimpleTestCase):
    def _message(self, exc):
        response = custom_exception_handler(exc, {})
        self.assertEqual(409, response.status_code)
        self.assertEqual({"message"}, set(response.data), response.data)
        return response.data["message"]

    def test_several_referencing_records_are_counted(self):
        exc = RestrictedError("Cannot delete some instances of model 'Dojo_User'", {Finding(id=1), Finding(id=2), Finding(id=3)})
        self.assertEqual(
            "It cannot be deleted while 3 other records still refer to it. Records that refer to it: finding.",
            self._message(exc),
        )

    def test_one_referencing_record_reads_in_the_singular(self):
        exc = RestrictedError("Cannot delete some instances of model 'Dojo_User'", {Finding(id=1)})
        self.assertEqual(
            "It cannot be deleted while 1 other record still refers to it. Records that refer to it: finding.",
            self._message(exc),
        )

    def test_each_kind_of_referencing_record_is_named_once(self):
        exc = RestrictedError("Cannot delete", {Finding(id=1), Finding(id=2), Product(id=3)})
        message = self._message(exc)
        self.assertTrue(message.endswith("Records that refer to it: finding, product."), message)

    def test_without_its_records_it_still_reads(self):
        exc = RestrictedError("Cannot delete some instances of model 'SLA_Configuration'", set())
        self.assertEqual("It cannot be deleted while other records still refer to it.", self._message(exc))

    def test_the_referencing_rows_are_never_named(self):
        exc = RestrictedError("Cannot delete", {Finding(id=7, title="secret finding title")})
        message = self._message(exc)
        self.assertNotIn("secret", message)
        self.assertNotIn("<Finding", message)
        self.assertNotIn("7", message)
