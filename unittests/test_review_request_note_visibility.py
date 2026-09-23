"""
Regression tests for the note created by a finding review request.

Requesting a review stores the reviewer instructions as a note on the finding.
That note used to be saved with ``private=True``, and ``visible_notes`` shows a
private note only to its author and superusers, so the one person the message
was written for (the assigned reviewer) could not read it. The note must be
public; the review-request form offers no private option.
"""

# Regression: the review-request note was saved private, so the assigned
# reviewer could not read the instructions they were asked to act on.

import datetime
import importlib

from django.apps import apps
from django.urls import reverse
from django.utils import timezone
from parameterized import parameterized

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
from dojo.notes.helper import visible_notes

from .dojo_test_case import DojoTestCase

ENTRY = "please downgrade to medium, compensating control is in place"

START = datetime.date(2026, 1, 1)
END = datetime.date(2026, 1, 2)

READERS = [("requester",), ("reviewer",)]


class ReviewRequestNoteVisibilityTest(DojoTestCase):

    """The review-request note is public, so the assigned reviewer can read it."""

    def setUp(self):
        self.requester = self._member("review-note-requester")
        self.reviewer = self._member("review-note-reviewer")

        product_type, _ = Product_Type.objects.get_or_create(name="review-note")
        self.product, _ = Product.objects.get_or_create(
            name="ReviewRequestNoteVisibilityTest", description="Test", prod_type=product_type,
        )
        for user in (self.requester, self.reviewer):
            self.product.authorized_users.add(user)
            Product_Member.objects.get_or_create(
                product=self.product, user=user, defaults={"role_id": 4},
            )

        engagement = Engagement.objects.create(
            name="review note", product=self.product, target_start=START, target_end=END,
        )
        test_type, _ = Test_Type.objects.get_or_create(name="review-note-tt")
        test = Test.objects.create(
            engagement=engagement, test_type=test_type,
            target_start=self._aware(START), target_end=self._aware(END),
        )
        self.finding = Finding.objects.create(
            title="review note finding", test=test, reporter=self.requester,
            severity="Info", numerical_severity="S4",
        )

    @staticmethod
    def _aware(day):
        return timezone.make_aware(datetime.datetime.combine(day, datetime.time()))

    def _member(self, username):
        user, _ = Dojo_User.objects.get_or_create(
            username=username, defaults={"is_superuser": False, "is_staff": False},
        )
        return user

    def _request_review(self):
        self.client.force_login(self.requester)
        response = self.client.post(
            reverse("request_finding_review", args=(self.finding.id,)),
            {"reviewers": [str(self.reviewer.id)], "entry": ENTRY},
            secure=True,
        )
        self.assertEqual(302, response.status_code)
        return Notes.objects.get(entry=f"Review Request: {ENTRY}")

    def test_review_request_note_is_stored_public(self):
        note = self._request_review()
        self.assertFalse(
            note.private,
            f"expected the review-request note to be public, persisted private={note.private}",
        )

    @parameterized.expand(READERS)
    def test_review_request_note_is_readable_by(self, reader_role):
        note = self._request_review()
        reader = {"requester": self.requester, "reviewer": self.reviewer}[reader_role]
        visible = visible_notes(self.finding.notes.all(), reader)
        self.assertIn(
            note, visible,
            f"expected the review-request note to be readable by the {reader_role}, "
            f"persisted private={note.private}",
        )


class ReviewRequestNoteMigrationTest(DojoTestCase):

    """The 0292 data migration flips only historical private review-request notes."""

    def test_migration_flips_only_private_review_request_notes(self):
        migration = importlib.import_module("dojo.db_migrations.0292_review_request_notes_public")
        author, _ = Dojo_User.objects.get_or_create(username="review-note-migration-author")
        review_note = Notes.objects.create(
            entry="Review Request: check the severity", author=author, private=True,
        )
        private_note = Notes.objects.create(
            entry="INTERNAL: unrelated private note", author=author, private=True,
        )
        quoting_note = Notes.objects.create(
            entry="Reply about the Review Request: keep this one private", author=author, private=True,
        )
        public_note = Notes.objects.create(
            entry="Review Request: was already public", author=author, private=False,
        )

        migration.make_review_request_notes_public(apps, None)

        review_note.refresh_from_db()
        private_note.refresh_from_db()
        quoting_note.refresh_from_db()
        public_note.refresh_from_db()
        self.assertFalse(
            review_note.private,
            f"expected the private review-request note to become public, private={review_note.private}",
        )
        self.assertTrue(
            private_note.private,
            "a private note without the review prefix must stay private",
        )
        self.assertTrue(
            quoting_note.private,
            "a private note merely containing the prefix mid-text must stay private",
        )
        self.assertFalse(public_note.private)
