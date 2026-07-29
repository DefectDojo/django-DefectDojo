"""
Regression tests: a database unique-constraint violation that reaches the API
layer must produce a client-actionable ``409 Conflict``, not a bare ``500``.

Two guards check uniqueness before the INSERT, and both are check-then-insert
rather than atomic:

* DRF builds a ``UniqueValidator`` for any serializer field backed by a model
  field with ``unique=True``, which SELECTs during validation.
* ``BaseModelWithoutTimeMeta.save()`` calls ``full_clean()`` — and so
  ``validate_unique()`` — but only when ``V3_FEATURE_LOCATIONS`` is enabled,
  since ``skip_validation`` defaults to ``not settings.V3_FEATURE_LOCATIONS``.

Concurrent writers can pass both: at the moment each ran its SELECT the winning
row was not committed yet. The loser's INSERT then hits the constraint and the
database raises ``IntegrityError``. Nothing in the DRF stack handled that, so it
fell through to the generic branch of ``custom_exception_handler`` and the caller
received ``500 Internal server error`` — no indication that the record it wanted
already exists, and an entry in error reporting that reads like an outage.

Reported from a production asset-create endpoint driven by a CI service account
running parallel jobs, which makes the losing writer routine rather than rare.

Only *unique* violations translate to 409. Other ``IntegrityError`` subtypes
(foreign key, not-null, check constraints) indicate a server-side defect and
must keep returning 500 so they stay visible.
"""

from unittest.mock import patch

from django.db import transaction
from django.db.utils import IntegrityError
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient, APITestCase

from dojo.api_v2.exception_handler import custom_exception_handler
from dojo.models import Product
from unittests.dojo_test_case import versioned_fixtures

# SQLSTATE 23505 = unique_violation.
UNIQUE_VIOLATION_SQLSTATE = "23505"

# Message shapes as the drivers word them, for the no-SQLSTATE fallback path.
POSTGRES_UNIQUE_MESSAGE = (
    'duplicate key value violates unique constraint "dojo_product_name_key"\n'
    "DETAIL:  Key (name)=(some asset) already exists."
)
MYSQL_UNIQUE_MESSAGE = "(1062, \"Duplicate entry 'some asset' for key 'name'\")"
FOREIGN_KEY_MESSAGE = (
    'update or delete on table "dojo_tagulous_test_tags" violates foreign key '
    'constraint "dojo_test_tags_tagulous_test_tags_i_6336441a_fk_dojo_tagu" '
    'on table "dojo_test_tags"\n'
    'DETAIL:  Key (id)=(1) is still referenced from table "dojo_test_tags".'
)
NOT_NULL_MESSAGE = 'null value in column "name" of relation "dojo_product" violates not-null constraint'


@versioned_fixtures
class UniqueViolationExceptionHandlerTest(APITestCase):

    """Coverage of the handler's IntegrityError branch."""

    fixtures = ["dojo_testdata.json"]

    def test_postgres_unique_violation_returns_409(self):
        response = custom_exception_handler(IntegrityError(POSTGRES_UNIQUE_MESSAGE), {})

        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 409)

    def test_mysql_duplicate_entry_returns_409(self):
        response = custom_exception_handler(IntegrityError(MYSQL_UNIQUE_MESSAGE), {})

        self.assertEqual(response.status_code, 409)

    def test_sqlstate_is_honoured_when_message_is_unrecognised(self):
        """
        Detection must not depend on driver wording.

        A driver that words the message differently but reports SQLSTATE 23505
        still has to be recognised, so the check reads the wrapped cause first.
        """

        class DriverError(Exception):
            sqlstate = UNIQUE_VIOLATION_SQLSTATE

        exc = IntegrityError("a future driver wording this differently")
        exc.__cause__ = DriverError()

        response = custom_exception_handler(exc, {})

        self.assertEqual(response.status_code, 409)

    def test_conflict_message_does_not_leak_database_internals(self):
        response = custom_exception_handler(IntegrityError(POSTGRES_UNIQUE_MESSAGE), {})

        message = response.data["message"]
        # Constraint name, table name and the offending value are database
        # internals / payload echoes. None of them belong in a response body.
        self.assertNotIn("dojo_product_name_key", message)
        self.assertNotIn("DETAIL", message)
        self.assertNotIn("some asset", message)
        self.assertIn("already exists", message.lower())

    def test_foreign_key_violation_still_returns_500(self):
        response = custom_exception_handler(IntegrityError(FOREIGN_KEY_MESSAGE), {})

        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 500)

    def test_not_null_violation_still_returns_500(self):
        response = custom_exception_handler(IntegrityError(NOT_NULL_MESSAGE), {})

        self.assertEqual(response.status_code, 500)

    def test_real_driver_unique_violation_returns_409(self):
        """
        Feed the handler the exception the database actually raises.

        The message-shape cases above are hand-built. This one provokes a
        genuine duplicate INSERT — ``skip_validation=True`` bypasses
        ``full_clean()`` exactly as the losing writer effectively does, since its
        uniqueness SELECT ran before the winning row was committed — and asserts
        both that the driver reports SQLSTATE 23505 and that the handler
        translates it.
        """
        existing = Product.objects.first()
        duplicate = Product(
            name=existing.name,
            description="created by a parallel CI job",
            prod_type=existing.prod_type,
        )

        # Inner atomic block so the failed statement does not poison the
        # surrounding test transaction.
        with transaction.atomic(), self.assertRaises(IntegrityError) as caught:
            duplicate.save(skip_validation=True)

        exc = caught.exception
        self.assertEqual(getattr(exc.__cause__, "sqlstate", None), UNIQUE_VIOLATION_SQLSTATE)

        response = custom_exception_handler(exc, {})

        self.assertEqual(response.status_code, 409)


@versioned_fixtures
class UniqueViolationApiTest(APITestCase):

    """Coverage through a real create endpoint and the configured handler."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        self.existing = Product.objects.first()

    def _post_duplicate(self):
        return self.client.post(
            reverse("asset-list"),
            {
                "name": self.existing.name,
                "description": "created by a parallel CI job",
                "organization": self.existing.prod_type_id,
            },
            format="json",
        )

    def test_duplicate_name_is_still_rejected_with_400(self):
        """The uncontended path is unchanged: DRF rejects before the INSERT."""
        response = self._post_duplicate()

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["name"][0].code, "unique")

    def test_lost_create_race_returns_409_not_500(self):
        """
        Both pre-INSERT uniqueness SELECTs are neutralised together.

        That is precisely what the losing writer experiences: neither its
        serializer-level check nor its model-level check could see the winning
        row, because that row was not committed until after both had run. With
        both bypassed the request reaches the INSERT and the database constraint
        is the only thing left to reject it.
        """
        with (
            patch("rest_framework.validators.UniqueValidator.__call__", return_value=None),
            patch.object(Product, "validate_unique", return_value=None),
        ):
            response = self._post_duplicate()

        self.assertEqual(response.status_code, 409)
        self.assertIn("already exists", response.data["message"].lower())

    def test_unique_name_still_creates_successfully(self):
        """Guard against the handler swallowing legitimate creates."""
        response = self.client.post(
            reverse("asset-list"),
            {
                "name": "an asset name not present in the fixtures",
                "description": "created by a parallel CI job",
                "organization": self.existing.prod_type_id,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 201)
