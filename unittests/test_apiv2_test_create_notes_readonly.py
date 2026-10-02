import logging

from django.utils import timezone
from rest_framework.authtoken.models import Token

from dojo.models import Engagement, Notes, Product, Product_Type, Test, Test_Type, User

from .dojo_test_case import DojoAPITestCase

logger = logging.getLogger(__name__)


class TestCreateNotesReadOnlyAPI(DojoAPITestCase):

    """notes should be read-only when creating a test (added through the notes endpoint instead)."""

    def setUp(self):
        user, _ = User.objects.get_or_create(username="admin", defaults={"is_superuser": True, "is_staff": True})
        token, _ = Token.objects.get_or_create(user=user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")

        product_type, _ = Product_Type.objects.get_or_create(name="notes-readonly-api")
        product, _ = Product.objects.get_or_create(
            name="TestCreateNotesReadOnlyAPI",
            description="Test",
            prod_type=product_type,
        )
        self.engagement, _ = Engagement.objects.get_or_create(
            name="notes readonly api",
            product=product,
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        self.test_type, _ = Test_Type.objects.get_or_create(name="Acunetix Scan")
        # a Note row that already exists independently of the create request
        self.existing_note = Notes.objects.create(entry="preexisting", author=user)

    def _payload(self, **overrides):
        payload = {
            "engagement": self.engagement.id,
            "test_type": self.test_type.id,
            "title": "notes readonly",
            "target_start": "2026-07-01T00:00:00Z",
            "target_end": "2026-07-02T00:00:00Z",
        }
        payload.update(overrides)
        return payload

    def test_notes_supplied_on_create_are_ignored(self):
        response = self.client.post("/api/v2/tests/", self._payload(notes=[self.existing_note.id]), format="json")
        self.assertEqual(201, response.status_code, response.content)
        body = response.json()
        # read side unchanged: notes is still part of the representation ...
        self.assertIn("notes", body)
        # ... but read-only, so the supplied id is not adopted by the new Test
        self.assertEqual([], body["notes"])
        self.assertEqual(0, Test.objects.get(id=body["id"]).notes.count())
