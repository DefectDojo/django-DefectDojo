"""
Regression tests for private note visibility.

The ``notes`` relation used to be serialized and rendered straight off the
parent object, so any user who could read a Finding, Test, Engagement or Risk
Acceptance received every note attached to it, including notes another user had
marked private. Every read path now goes through ``visible_notes``.
"""

import datetime
from types import SimpleNamespace

from django.test import Client
from django.urls import reverse
from django.utils import timezone
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
from dojo.notes.api.serializer import NoteSerializer
from dojo.notes.helper import visible_notes

from .dojo_test_case import DojoAPITestCase

PRIVATE = "INTERNAL: note visibility private entry"
PUBLIC = "note visibility public entry"

START = datetime.date(2026, 1, 1)
END = datetime.date(2026, 1, 2)


class NoteVisibilityTest(DojoAPITestCase):

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
            name="NoteVisibilityTest", description="Test", prod_type=product_type,
        )
        for user in (self.author, self.colleague):
            self.product.authorized_users.add(user)
            Product_Member.objects.get_or_create(
                product=self.product, user=user, defaults={"role_id": 4},
            )

        self.engagement = Engagement.objects.create(
            name="note visibility", product=self.product,
            target_start=START, target_end=END,
        )
        test_type, _ = Test_Type.objects.get_or_create(name="note-visibility-tt")
        self.test = Test.objects.create(
            engagement=self.engagement, test_type=test_type,
            target_start=self._aware(START), target_end=self._aware(END),
        )
        self.finding = Finding.objects.create(
            title="note visibility finding", test=self.test, reporter=self.author,
            severity="Info", numerical_severity="S4",
        )

        for parent in (self.finding, self.test, self.engagement):
            parent.notes.add(Notes.objects.create(entry=PRIVATE, author=self.author, private=True))
            parent.notes.add(Notes.objects.create(entry=PUBLIC, author=self.author, private=False))

    @staticmethod
    def _aware(day):
        return timezone.make_aware(datetime.datetime.combine(day, datetime.time()))

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

    def _entries(self, user):
        return {n.entry for n in visible_notes(self.finding.notes.all(), user)}

    # ---- the API -----------------------------------------------------------

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

    # ---- the rule the UI shares with the serializer ------------------------

    def test_helper_gives_the_author_both(self):
        self.assertEqual({PRIVATE, PUBLIC}, self._entries(self.author))

    def test_helper_gives_a_colleague_only_the_public_one(self):
        self.assertEqual({PUBLIC}, self._entries(self.colleague))

    def test_helper_gives_a_superuser_both(self):
        self.assertEqual({PRIVATE, PUBLIC}, self._entries(self.superuser))

    def test_helper_without_a_user_gives_only_the_public_one(self):
        self.assertEqual({PUBLIC}, self._entries(None))

    def test_helper_accepts_an_already_evaluated_list(self):
        """
        A paginated notes page arrives as a list, not a queryset.

        DRF pagination evaluates the queryset before serialization, so
        ``VisibleNotesSerializer.to_representation`` hands ``visible_notes`` a
        plain ``list``. The non-superuser and no-user branches used to call
        ``list.filter(...)``, so every paginated notes read 500'd for a
        non-superuser. The rule must apply identically whether it is given a
        queryset or an already-evaluated page.
        """
        page = list(self.finding.notes.all())  # exactly what DRF pagination passes

        def entries(user):
            return {n.entry for n in visible_notes(page, user)}

        self.assertEqual({PUBLIC}, entries(self.colleague))
        self.assertEqual({PRIVATE, PUBLIC}, entries(self.author))
        self.assertEqual({PRIVATE, PUBLIC}, entries(self.superuser))
        self.assertEqual({PUBLIC}, entries(None))

    def test_finding_page_context_is_filtered(self):
        client = Client()
        client.force_login(self.colleague)
        response = client.get(reverse("view_finding", args=(self.finding.id,)))
        self.assertEqual(200, response.status_code)
        entries = {n.entry for n in response.context["notes"]}
        self.assertNotIn(PRIVATE, entries)
        self.assertIn(PUBLIC, entries)

    # ---- the rule when the caller has already materialised the notes -------
    #
    # ``VisibleNotesSerializer`` is a ``ListSerializer``, and a list endpoint
    # hands one a plain list rather than a queryset: DRF's
    # ``paginate_queryset`` returns ``list(queryset[offset:limit])``. A
    # queryset-only helper raises ``AttributeError: 'list' object has no
    # attribute 'filter'`` there, which surfaces as a 500 rather than as a
    # visibility bug -- and only for non-superusers, because a superuser
    # returns before any filtering happens.

    def _entries_from_list(self, user):
        return {n.entry for n in visible_notes(list(self.finding.notes.all()), user)}

    def test_helper_filters_an_already_materialised_list_for_a_colleague(self):
        self.assertEqual({PUBLIC}, self._entries_from_list(self.colleague))

    def test_helper_filters_an_already_materialised_list_for_the_author(self):
        self.assertEqual({PRIVATE, PUBLIC}, self._entries_from_list(self.author))

    def test_helper_filters_an_already_materialised_list_for_a_superuser(self):
        self.assertEqual({PRIVATE, PUBLIC}, self._entries_from_list(self.superuser))

    def test_helper_filters_an_already_materialised_list_without_a_user(self):
        self.assertEqual({PUBLIC}, self._entries_from_list(None))

    def test_note_serializer_accepts_a_paginated_page(self):
        """The path that 500s: a page is a list, and the serializer filters it."""
        page = list(self.finding.notes.all())

        serializer = NoteSerializer(
            page, many=True, context={"request": SimpleNamespace(user=self.colleague)},
        )

        self.assertEqual({PUBLIC}, {row["entry"] for row in serializer.data})
