"""
Regression test for the note count on the UI findings list and the test page.

Both pages prefetch ``notes`` and render ``finding.notes.all|visible_to:user``.
For a non-superuser, ``visible_notes`` filters a prefetched relation in Python
and returns a list, so the templates have to count it with ``|length``. A
``.count`` lookup on a list renders as an empty string, which showed "()"
instead of the number of notes.
"""

import datetime

from django.urls import reverse
from django.utils import timezone

from dojo.authorization.roles_permissions import Roles
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

from .dojo_test_case import DojoTestCase

START = datetime.date(2026, 1, 1)
END = datetime.date(2026, 1, 2)


class NoteCountUIListsTest(DojoTestCase):

    def setUp(self):
        self.author, _ = Dojo_User.objects.get_or_create(
            username="note-count-author", defaults={"is_superuser": False, "is_staff": False},
        )
        self.reader, _ = Dojo_User.objects.get_or_create(
            username="note-count-reader", defaults={"is_superuser": False, "is_staff": False},
        )
        self.superuser, _ = Dojo_User.objects.get_or_create(
            username="note-count-super", defaults={"is_superuser": True, "is_staff": True},
        )
        product_type, _ = Product_Type.objects.get_or_create(name="note-count")
        product, _ = Product.objects.get_or_create(
            name="NoteCountUIListsTest", description="Test", prod_type=product_type,
        )
        for user in (self.author, self.reader):
            Product_Member.objects.get_or_create(product=product, user=user, defaults={"role_id": Roles.Reader})
            # Legacy authorization reads ``authorized_users``; mirror the RBAC row.
            product.authorized_users.add(user)
        engagement = Engagement.objects.create(
            name="note count", product=product, target_start=START, target_end=END,
        )
        test_type, _ = Test_Type.objects.get_or_create(name="note-count-tt")
        self.test = Test.objects.create(
            engagement=engagement, test_type=test_type,
            target_start=timezone.make_aware(datetime.datetime.combine(START, datetime.time())),
            target_end=timezone.make_aware(datetime.datetime.combine(END, datetime.time())),
        )
        self.finding = Finding.objects.create(
            title="note count finding", test=self.test, reporter=self.author,
            severity="High", numerical_severity="S1", active=True, verified=False,
        )
        # Two notes the reader may see, and one private note by someone else.
        for entry, private in (("public one", False), ("public two", False), ("private", True)):
            self.finding.notes.add(Notes.objects.create(entry=entry, author=self.author, private=private))

    def _note_link(self, user, url):
        self.client.force_login(user)
        response = self.client.get(url)
        self.assertEqual(200, response.status_code)
        return response.content.decode()

    def _urls(self):
        return {
            "findings list": reverse("open_findings"),
            "test page": reverse("view_test", args=(self.test.id,)),
        }

    def test_non_superuser_sees_the_count_of_visible_notes(self):
        for page, url in self._urls().items():
            with self.subTest(page=page):
                body = self._note_link(self.reader, url)
                # The page as a whole does not parse as strict HTML, so match the link text directly.
                self.assertRegex(body, r'alt="2 notes">\s*\(2\)\s*</a>')
                self.assertNotRegex(body, r'alt=" note">\s*\(\)')

    def test_superuser_sees_every_note_counted(self):
        for page, url in self._urls().items():
            with self.subTest(page=page):
                body = self._note_link(self.superuser, url)
                self.assertRegex(body, r'alt="3 notes">\s*\(3\)\s*</a>')
