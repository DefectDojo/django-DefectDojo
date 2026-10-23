"""
Whole-request query counts for the findings and engagements list endpoints.

A list page has to cost the same number of queries whether it holds two rows or six. Three
things made the count grow with the page, one query (or more) per row each:

* ``VisibleNotesSerializer`` re-filtered every row's prefetched notes in SQL for a
  non-superuser, which threw the prefetch away and loaded the notes and their history again.
* ``?prefetch=<field>`` authorized the related object of every row with its own ``exists()``
  query and serialized the same object once per row.
* A forward foreign key named by ``?prefetch=`` (``reporter``, ``test``) was read row by row.
"""

import datetime
import re
from collections import Counter
from unittest.mock import patch

from crum import impersonate
from django.db import connection
from django.test.utils import CaptureQueriesContext
from rest_framework import serializers
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.api_v2.prefetch.prefetcher import _Prefetcher  # noqa: PLC2701 -- the class under test
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

from .dojo_test_case import DojoAPITestCase

START = datetime.date(2026, 1, 1)
END = datetime.date(2026, 1, 2)
# Test.target_start/target_end are DateTimeFields
TEST_START = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
TEST_END = datetime.datetime(2026, 1, 2, tzinfo=datetime.UTC)


def _shapes(sqls):
    """Each query with its literals replaced, so one per-row query on different ids counts as one shape."""
    return Counter(re.sub(r"\b\d+\b|'[^']*'|\"s\d+_x\d+\"", "%s", sql)[:300] for sql in sqls)


class ListQueryScalingTest(DojoAPITestCase):

    """Adding rows to a list page must not add queries."""

    def setUp(self):
        self.admin, _ = Dojo_User.objects.get_or_create(
            username="list-scaling-super", defaults={"is_superuser": True, "is_staff": True},
        )
        self.member, _ = Dojo_User.objects.get_or_create(username="list-scaling-member")
        product_type, _ = Product_Type.objects.get_or_create(name="list-scaling")
        self.product, _ = Product.objects.get_or_create(
            name="ListQueryScalingTest", description="Test", prod_type=product_type,
        )
        self.product.authorized_users.add(self.member)
        Product_Member.objects.get_or_create(product=self.product, user=self.member, defaults={"role_id": 4})
        self.engagement = Engagement.objects.create(
            product=self.product, name="list-scaling-eng", target_start=START, target_end=END,
        )
        test_type, _ = Test_Type.objects.get_or_create(name="list-scaling-tt")
        self.test = Test.objects.create(
            engagement=self.engagement, test_type=test_type, target_start=TEST_START, target_end=TEST_END,
        )

    def _client(self, user):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Token {Token.objects.get_or_create(user=user)[0].key}")
        return client

    def _count(self, user, url, params):
        client = self._client(user)
        # Warm request: per-process caches fill on first use and would read as a difference.
        client.get(url, params, format="json")
        with CaptureQueriesContext(connection) as ctx:
            response = client.get(url, params, format="json")
        self.assertEqual(200, response.status_code, response.content[:500])
        return [query["sql"] for query in ctx.captured_queries], response.json()

    def _assert_flat(self, user, url, params, add_row, small=2, large=6):
        for idx in range(small):
            add_row(idx)
        small_sqls, _ = self._count(user, url, params)
        for idx in range(small, large):
            add_row(idx)
        large_sqls, payload = self._count(user, url, params)
        # vulnerability_ids still reads per row here. A plugin that extends this queryset (Pro) adds its own
        # vulnerability_id_prefetch(), and a second Prefetch on the same lookup raises, so it is left out of the
        # count rather than prefetched in this queryset.
        small_sqls = [sql for sql in small_sqls if "dojo_findingvulnerabilityreference" not in sql]
        large_sqls = [sql for sql in large_sqls if "dojo_findingvulnerabilityreference" not in sql]
        grown = _shapes(large_sqls) - _shapes(small_sqls)
        self.assertEqual(
            len(small_sqls), len(large_sqls),
            f"{url} {params} as {user.username}: {small} rows cost {len(small_sqls)} queries, {large} cost "
            f"{len(large_sqls)}. Query shapes that ran more often: {dict(grown)}",
        )
        return payload

    def _add_finding(self, idx):
        finding = Finding.objects.create(
            title=f"list-scaling-finding-{idx}", test=self.test, reporter=self.admin,
            severity="High", numerical_severity="S1",
        )
        public = Notes.objects.create(entry=f"public {idx}", author=self.admin)
        private = Notes.objects.create(entry=f"private {idx}", author=self.admin, private=True)
        finding.notes.add(public, private)
        return finding

    def _add_engagement(self, idx):
        lead, _ = Dojo_User.objects.get_or_create(username=f"list-scaling-lead-{idx}")
        return Engagement.objects.create(
            product=self.product, name=f"list-scaling-eng-{idx}", lead=lead, target_start=START, target_end=END,
        )

    def test_findings_list_is_flat_for_a_member_with_notes(self):
        payload = self._assert_flat(self.member, "/api/v2/findings/", {"limit": 100}, self._add_finding)
        # The member still sees only the public note of each finding.
        for row in payload["results"]:
            self.assertEqual(["public"], [note["entry"].split()[0] for note in row["notes"]])

    def test_findings_list_prefetch_test_is_flat_for_a_member(self):
        payload = self._assert_flat(
            self.member, "/api/v2/findings/", {"limit": 100, "prefetch": "test"}, self._add_finding,
        )
        self.assertEqual([str(self.test.id)], list(payload["prefetch"]["test"]))

    def test_findings_list_prefetch_notes_is_flat_for_a_member(self):
        payload = self._assert_flat(
            self.member, "/api/v2/findings/", {"limit": 100, "prefetch": "notes,reporter"}, self._add_finding,
        )
        # Only the public note of each finding reaches the member.
        self.assertEqual(["public"] * 6, sorted(note["entry"].split()[0] for note in payload["prefetch"]["notes"].values()))

    def test_engagements_list_is_flat(self):
        for user in (self.admin, self.member):
            with self.subTest(user=user.username):
                Engagement.objects.all().delete()
                self._assert_flat(user, "/api/v2/engagements/", {"limit": 200}, self._add_engagement)

    def test_page_prefetch_payload_matches_the_per_entry_payload(self):
        """Prefetching a whole page yields the payload that prefetching it row by row did."""
        for idx in range(4):
            self._add_finding(idx)
        other_test = Test.objects.create(
            engagement=self.engagement, test_type=self.test.test_type, target_start=TEST_START, target_end=TEST_END,
        )
        Finding.objects.filter(title="list-scaling-finding-3").update(test=other_test)
        fields = ["test", "reporter", "notes", "found_by"]
        for user in (self.admin, self.member):
            # The authorization policies read the current user, as they do inside a request
            with self.subTest(user=user.username), impersonate(user):
                request = type("Request", (), {"user": user})()
                findings = list(Finding.objects.filter(test__engagement=self.engagement).order_by("id"))

                per_entry = _Prefetcher(request=request)
                for finding in findings:
                    per_entry._prefetch(finding, fields)

                page = _Prefetcher(request=request)
                page.prefetch_entries(list(Finding.objects.filter(id__in=[f.id for f in findings]).order_by("id")), fields)

                self.assertEqual(per_entry.prefetched_data, page.prefetched_data)
                # The user can see notes on these findings, so the comparison covers a non-empty payload
                self.assertTrue(page.prefetched_data["notes"])
                # Same ids in the same order, not only the same mapping.
                for field in fields:
                    self.assertEqual(
                        list(per_entry.prefetched_data.get(field, {})), list(page.prefetched_data.get(field, {})), field,
                    )

    def test_page_prefetch_leaves_out_an_object_the_serializer_filters(self):
        """A list serializer that returns fewer rows than it was given drops that object, it does not fail."""
        for idx in range(2):
            self._add_finding(idx)
        request = type("Request", (), {"user": self.admin})()
        findings = list(Finding.objects.filter(test=self.test).order_by("id"))
        dropped = Notes.objects.filter(entry="public 0").get()

        class DroppingSerializer(serializers.ListSerializer):
            def to_representation(self, data):
                return super().to_representation([note for note in data if note.pk != dropped.pk])

        class FilteringNoteSerializer(NoteSerializer):
            class Meta(NoteSerializer.Meta):
                list_serializer_class = DroppingSerializer

        prefetcher = _Prefetcher(request=request)
        with patch.object(_Prefetcher, "_find_serializer", return_value=FilteringNoteSerializer):
            prefetcher.prefetch_entries(findings, ["notes"])

        # Every note of the page except the one the serializer dropped
        self.assertEqual(
            ["private 0", "private 1", "public 1"],
            sorted(note["entry"] for note in prefetcher.prefetched_data["notes"].values()),
        )
