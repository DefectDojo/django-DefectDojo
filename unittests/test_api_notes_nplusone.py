from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils.timezone import now
from rest_framework.test import APITestCase

from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    NoteHistory,
    Notes,
    Product,
    Product_Type,
    Risk_Acceptance,
    Test,
    Test_Type,
)


class TestNotesListNPlusOne(APITestCase):

    """
    Regression: list endpoints that embed NoteSerializer (findings, engagements, tests,
    risk_acceptance) must load note authors/editors/history in bulk via notes_prefetch().
    A flat prefetch of the notes relation leaves NoteSerializer to lazy-load author, editor,
    note_type and history__current_editor per note, so the query count grows with every note.
    Each test pins the fix by asserting the query count is identical with 1 and with 5 notes.
    """

    @classmethod
    def setUpTestData(cls):
        cls.user = Dojo_User.objects.create(username="np1_user", is_staff=True, is_superuser=True)
        cls.prod_type = Product_Type.objects.create(name="NP1 Product Type")
        cls.product = Product.objects.create(name="NP1 Product", prod_type=cls.prod_type, description="NP1")
        cls.engagement = Engagement.objects.create(
            name="NP1 Engagement", product=cls.product, target_start=now(), target_end=now(),
        )
        cls.test_type = Test_Type.objects.create(name="NP1 Test Type")
        cls.test = Test.objects.create(
            title="NP1 Test", engagement=cls.engagement, test_type=cls.test_type,
            target_start=now(), target_end=now(),
        )
        cls.finding = Finding.objects.create(title="NP1 Finding", test=cls.test, reporter=cls.user, severity="High")
        cls.risk_acceptance = Risk_Acceptance.objects.create(name="NP1 RA", owner=cls.user)
        cls.risk_acceptance.engagement_set.add(cls.engagement)

    def setUp(self):
        self.client.force_authenticate(user=self.user)

    def _add_note(self, obj):
        # An edited note with a history entry exercises every relation NoteSerializer renders.
        note = Notes.objects.create(entry="np1 note", author=self.user, edited=True, editor=self.user)
        history = NoteHistory.objects.create(data="np1 history", current_editor=self.user)
        note.history.add(history)
        obj.notes.add(note)

    def _query_count(self, url):
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.content[:1000])
        return len(ctx.captured_queries)

    def _assert_count_independent_of_notes(self, obj, url):
        self._add_note(obj)
        self._query_count(url)  # warm-up: fills ContentType and other first-request caches
        with_one_note = self._query_count(url)
        for _ in range(4):
            self._add_note(obj)
        with_five_notes = self._query_count(url)
        self.assertEqual(
            with_one_note, with_five_notes,
            f"{url} ran {with_five_notes - with_one_note} extra queries for 4 extra notes (N+1 on notes)",
        )

    def test_finding_list_query_count_independent_of_notes(self):
        self._assert_count_independent_of_notes(self.finding, f"/api/v2/findings/?id={self.finding.id}")

    def test_engagement_list_query_count_independent_of_notes(self):
        self._assert_count_independent_of_notes(self.engagement, f"/api/v2/engagements/?id={self.engagement.id}")

    def test_test_list_query_count_independent_of_notes(self):
        self._assert_count_independent_of_notes(self.test, f"/api/v2/tests/?id={self.test.id}")

    def test_risk_acceptance_list_query_count_independent_of_notes(self):
        self._assert_count_independent_of_notes(self.risk_acceptance, f"/api/v2/risk_acceptance/?id={self.risk_acceptance.id}")
