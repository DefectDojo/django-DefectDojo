"""
v2-parity port of #15407: a database unique-constraint violation that reaches the v3 API layer
must produce a client-actionable ``409 Conflict`` problem+json, not a bare 500.

The v3 create/rename routes rely on the model's ``full_clean()`` (``validate_unique``) rejecting a
duplicate with a 400 before the INSERT — but that check and the INSERT are not atomic. Two
concurrent writers both pass validation (the winning row is not committed when the loser SELECTs)
and the loser hits the database constraint, raising ``IntegrityError``. Without a registered
handler ninja lets that escape as a 500. Only *unique* violations translate to 409; other
``IntegrityError`` subtypes (foreign key, not-null, check constraints) indicate a server-side
defect and must keep surfacing as a 500.
"""
from unittest.mock import patch

from django.db.utils import IntegrityError
from django.test import RequestFactory

from dojo.api_v3.errors import _handle_integrity_error  # noqa: PLC2701 -- focused unit test of the re-raise branch
from dojo.models import Product_Type

from .base import ApiV3TestCase

FOREIGN_KEY_MESSAGE = (
    'update or delete on table "dojo_product" violates foreign key '
    'constraint "dojo_engagement_product_id_fk" on table "dojo_engagement"\n'
    'DETAIL:  Key (id)=(1) is still referenced from table "dojo_engagement".'
)


class TestApiV3UniqueViolationConflict(ApiV3TestCase):

    def setUp(self):
        super().setUp()
        self.existing = Product_Type.objects.first()

    def _post_duplicate(self):
        return self.client.post(
            self.v3_url("organizations"), {"name": self.existing.name}, format="json",
        )

    def test_duplicate_name_is_still_rejected_with_400(self):
        """The uncontended path is unchanged: model validate_unique rejects before the INSERT."""
        response = self._post_duplicate()
        self.assertEqual(400, response.status_code, response.content[:500])
        self.assertTrue(response.json()["type"].endswith("#error-validation"))

    def test_lost_create_race_returns_409_problem(self):
        """
        Neutralising ``validate_unique`` is precisely what the losing writer experiences: its
        uniqueness SELECT ran before the winning row was committed, so the request reaches the
        INSERT and the database constraint is the only thing left to reject it.
        """
        with patch.object(Product_Type, "validate_unique", return_value=None):
            response = self._post_duplicate()

        self.assertEqual(409, response.status_code, response.content[:500])
        self.assertEqual("application/problem+json", response["Content-Type"])
        body = response.json()
        self.assertEqual(409, body["status"])
        self.assertTrue(
            body["type"].endswith("#error-conflict"),
            f"expected type ...#error-conflict, got {body['type']}",
        )
        # Constraint name, table name and the offending value are database internals / payload
        # echoes. None of them belong in a response body.
        detail = body["detail"]
        self.assertNotIn(self.existing.name, detail)
        self.assertNotIn("dojo_", detail)
        self.assertIn("already exists", detail.lower())

    def test_unique_name_still_creates_successfully(self):
        """Guard against the handler swallowing legitimate creates."""
        response = self.client.post(
            self.v3_url("organizations"),
            {"name": "an organization name not present in the fixtures"},
            format="json",
        )
        self.assertEqual(201, response.status_code, response.content[:500])

    def test_foreign_key_violation_is_reraised_for_the_500_path(self):
        """Non-unique IntegrityErrors are not conflicts: the handler re-raises them."""
        request = RequestFactory().post("/api/v3/organizations")
        with self.assertRaises(IntegrityError):
            _handle_integrity_error(request, IntegrityError(FOREIGN_KEY_MESSAGE))
