"""
Regression tests for private notes on the note UI routes.

``visible_notes`` covers every path that *displays* a note. The three routes
under ``dojo/notes/ui`` resolve a note by id instead, and used to gate only on
the requester's permission on the parent object, so a member who was not the
author could read a private note, rewrite it, clear its private flag, or delete
it. Each route is exercised once per value of ``SUPPORTED_PAGES``.
"""

import datetime

from django.urls import reverse
from django.utils import timezone
from parameterized import parameterized

from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    NoteHistory,
    Notes,
    Product,
    Product_Member,
    Product_Type,
    Test,
    Test_Type,
)

from .dojo_test_case import DojoTestCase

PRIVATE = "INTERNAL: private note ui entry"
SUPERSEDED = "INTERNAL: private note ui entry the author edited out"
PUBLIC = "public note ui entry"
REWRITE = "rewritten by someone who is not the author"

START = datetime.date(2026, 1, 1)
END = datetime.date(2026, 1, 2)

PAGES = [("engagement",), ("test",), ("finding",)]


class NoteUIPrivateAuthzTest(DojoTestCase):

    """A private note is reachable through these routes by its author only."""

    def setUp(self):
        self.author = self._member("note-ui-author")
        self.colleague = self._member("note-ui-colleague")
        self.superuser, _ = Dojo_User.objects.get_or_create(
            username="note-ui-super",
            defaults={"is_superuser": True, "is_staff": True},
        )

        product_type, _ = Product_Type.objects.get_or_create(name="note-ui")
        self.product, _ = Product.objects.get_or_create(
            name="NoteUIPrivateAuthzTest", description="Test", prod_type=product_type,
        )
        for user in (self.author, self.colleague):
            self.product.authorized_users.add(user)
            Product_Member.objects.get_or_create(
                product=self.product, user=user, defaults={"role_id": 4},
            )

        self.engagement = Engagement.objects.create(
            name="note ui", product=self.product, target_start=START, target_end=END,
        )
        test_type, _ = Test_Type.objects.get_or_create(name="note-ui-tt")
        self.test = Test.objects.create(
            engagement=self.engagement, test_type=test_type,
            target_start=self._aware(START), target_end=self._aware(END),
        )
        self.finding = Finding.objects.create(
            title="note ui finding", test=self.test, reporter=self.author,
            severity="Info", numerical_severity="S4",
        )

        self.parents = {
            "engagement": self.engagement,
            "test": self.test,
            "finding": self.finding,
        }
        self.private = {}
        self.public = {}
        for page, parent in self.parents.items():
            private = Notes.objects.create(entry=PRIVATE, author=self.author, private=True)
            public = Notes.objects.create(entry=PUBLIC, author=self.author, private=False)
            # A revision the author has already edited out. It outlives the note's
            # current text, so the history route has to withhold it too.
            private.history.add(NoteHistory.objects.create(
                data=SUPERSEDED, time=timezone.now(), current_editor=self.author,
            ))
            parent.notes.add(private)
            parent.notes.add(public)
            self.private[page] = private
            self.public[page] = public

    @staticmethod
    def _aware(day):
        return timezone.make_aware(datetime.datetime.combine(day, datetime.time()))

    def _member(self, username):
        user, _ = Dojo_User.objects.get_or_create(
            username=username, defaults={"is_superuser": False, "is_staff": False},
        )
        return user

    def _url(self, name, note, page):
        return reverse(name, args=(note.id, page, self.parents[page].id))

    # ---- reads -------------------------------------------------------------

    @parameterized.expand(PAGES)
    def test_edit_form_denies_a_non_author_and_leaks_nothing(self, page):
        self.client.force_login(self.colleague)
        response = self.client.get(self._url("edit_note", self.private[page], page))
        self.assertEqual(400, response.status_code)
        self.assertNotIn(PRIVATE, response.content.decode())

    @parameterized.expand(PAGES)
    def test_history_denies_a_non_author_and_leaks_no_superseded_revision(self, page):
        self.client.force_login(self.colleague)
        response = self.client.get(self._url("note_history", self.private[page], page))
        self.assertEqual(400, response.status_code)
        body = response.content.decode()
        self.assertNotIn(PRIVATE, body)
        self.assertNotIn(SUPERSEDED, body)

    @parameterized.expand(PAGES)
    def test_author_still_reaches_their_own_private_note(self, page):
        self.client.force_login(self.author)
        response = self.client.get(self._url("edit_note", self.private[page], page))
        self.assertEqual(200, response.status_code)
        self.assertIn(PRIVATE, response.content.decode())

        response = self.client.get(self._url("note_history", self.private[page], page))
        self.assertEqual(200, response.status_code)
        self.assertIn(SUPERSEDED, response.content.decode())

    @parameterized.expand(PAGES)
    def test_superuser_still_reaches_the_private_note(self, page):
        self.client.force_login(self.superuser)
        response = self.client.get(self._url("edit_note", self.private[page], page))
        self.assertEqual(200, response.status_code)
        self.assertIn(PRIVATE, response.content.decode())

    # ---- writes ------------------------------------------------------------

    @parameterized.expand(PAGES)
    def test_non_author_cannot_rewrite_a_private_note(self, page):
        note = self.private[page]
        self.client.force_login(self.colleague)
        response = self.client.post(
            self._url("edit_note", note, page), {"entry": REWRITE, "private": "on"},
        )
        self.assertEqual(400, response.status_code)
        note.refresh_from_db()
        self.assertEqual(PRIVATE, note.entry)
        self.assertTrue(note.private)

    @parameterized.expand(PAGES)
    def test_non_author_cannot_clear_the_private_flag(self, page):
        note = self.private[page]
        self.client.force_login(self.colleague)
        response = self.client.post(self._url("edit_note", note, page), {"entry": REWRITE})
        self.assertEqual(400, response.status_code)
        note.refresh_from_db()
        self.assertTrue(note.private)

    @parameterized.expand(PAGES)
    def test_non_author_cannot_delete_a_private_note(self, page):
        note = self.private[page]
        self.client.force_login(self.colleague)
        response = self.client.post(self._url("delete_note", note, page), {"id": note.id})
        self.assertEqual(400, response.status_code)
        self.assertTrue(Notes.objects.filter(id=note.id).exists())

    # ---- a shared note stays editable, and its flag stays the author's -----

    @parameterized.expand(PAGES)
    def test_non_author_may_still_edit_a_shared_note(self, page):
        note = self.public[page]
        self.client.force_login(self.colleague)
        response = self.client.post(self._url("edit_note", note, page), {"entry": REWRITE})
        self.assertEqual(302, response.status_code)
        note.refresh_from_db()
        self.assertEqual(REWRITE, note.entry)

    @parameterized.expand(PAGES)
    def test_non_author_cannot_make_a_shared_note_private(self, page):
        note = self.public[page]
        self.client.force_login(self.colleague)
        response = self.client.post(
            self._url("edit_note", note, page), {"entry": REWRITE, "private": "on"},
        )
        self.assertEqual(302, response.status_code)
        note.refresh_from_db()
        self.assertFalse(note.private)

    @parameterized.expand(PAGES)
    def test_author_may_still_change_their_own_flag(self, page):
        note = self.public[page]
        self.client.force_login(self.author)
        response = self.client.post(
            self._url("edit_note", note, page), {"entry": REWRITE, "private": "on"},
        )
        self.assertEqual(302, response.status_code)
        note.refresh_from_db()
        self.assertTrue(note.private)
