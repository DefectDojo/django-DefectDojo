"""
Regression tests for private note visibility on the API.

The ``notes`` relation used to be serialized straight off the parent object,
so any user who could read a Finding, Test, Engagement or Risk Acceptance
received every note attached to it, including notes another user had marked
private. ``NoteSerializer`` now filters through ``VisibleNotesSerializer``.
"""

from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Notes,
    Product,
    Product_Member,
    Product_Type,
    Test,
    Test_Type,
)

from .dojo_test_case import DojoAPITestCase

PRIVATE = "INTERNAL: note visibility private entry"
PUBLIC = "note visibility public entry"


class NoteVisibilityAPITest(DojoAPITestCase):

    """A private note reaches its author and no other member of the product."""

    def setUp(self):
        self.author = self._member("note-visibility-author")
        self.colleague = self._member("note-visibility-colleague")
        self.superuser, _ = Dojo_User.objects.get_or_create(
            username="note-visibility-super",
            defaults={"is_superuser": True, "is_staff": True},
        )

        product_type, _ = Product_Type.objects.get_or_create(name="note-visibility")
        self.product, _ = Product.objects.get_or_create(
            name="NoteVisibilityAPITest", description="Test", prod_type=product_type,
        )
        for user in (self.author, self.colleague):
            self.product.authorized_users.add(user)
            Product_Member.objects.get_or_create(
                product=self.product, user=user, defaults={"role_id": 4},
            )

        self.engagement = Engagement.objects.create(
            name="note visibility", product=self.product,
            target_start="2026-01-01", target_end="2026-01-02",
        )
        test_type, _ = Test_Type.objects.get_or_create(name="note-visibility-tt")
        self.test = Test.objects.create(
            engagement=self.engagement, test_type=test_type,
            target_start="2026-01-01", target_end="2026-01-02",
        )
        self.finding = Finding.objects.create(
            title="note visibility finding", test=self.test, reporter=self.author,
            severity="Info", numerical_severity="S4",
        )

        for parent in (self.finding, self.test, self.engagement):
            parent.notes.add(Notes.objects.create(entry=PRIVATE, author=self.author, private=True))
            parent.notes.add(Notes.objects.create(entry=PUBLIC, author=self.author, private=False))

    def _member(self, username):
        user, _ = Dojo_User.objects.get_or_create(
            username=username, defaults={"is_superuser": False, "is_staff": False},
        )
        return user

    def _client(self, user):
        token, _ = Token.objects.get_or_create(user=user)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        return client

    def _paths(self):
        return [
            f"/api/v2/findings/{self.finding.id}/",
            f"/api/v2/findings/{self.finding.id}/notes/",
            f"/api/v2/tests/{self.test.id}/",
            f"/api/v2/tests/{self.test.id}/notes/",
            f"/api/v2/engagements/{self.engagement.id}/",
            f"/api/v2/engagements/{self.engagement.id}/notes/",
        ]

    def _body(self, user, path):
        response = self._client(user).get(path)
        self.assertEqual(200, response.status_code, f"{path}: {response.content[:300]}")
        return response.content.decode()

    def test_colleague_does_not_receive_another_members_private_note(self):
        for path in self._paths():
            body = self._body(self.colleague, path)
            self.assertNotIn(PRIVATE, body, path)
            self.assertIn(PUBLIC, body, path)

    def test_author_still_receives_their_own_private_note(self):
        for path in self._paths():
            body = self._body(self.author, path)
            self.assertIn(PRIVATE, body, path)
            self.assertIn(PUBLIC, body, path)

    def test_superuser_still_receives_every_note(self):
        for path in self._paths():
            self.assertIn(PRIVATE, self._body(self.superuser, path))

    def test_generated_report_carries_no_private_note(self):
        response = self._client(self.colleague).post(
            f"/api/v2/tests/{self.test.id}/generate_report/",
            {"include_finding_notes": True}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content[:300])
        self.assertNotIn(PRIVATE, response.content.decode())
