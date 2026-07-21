"""
Cursor (keyset) pagination contract tests for API v3 (D4 / §4.3).

Covers the forward-only, opaque-signed cursor mode added on top of the offset default:
full-walk correctness, the keyset-safe ordering variants + per-resource allowed sets, tamper/
ordering-mismatch rejection, composition with filters/include/fields/expand, and constant
(count-free) query cost per page. Offset mode is exercised unchanged by ``test_apiv3_findings``.
"""
from __future__ import annotations

import datetime
import json
from urllib.parse import unquote, urlsplit

from django.db import connection
from django.test.utils import CaptureQueriesContext

from dojo.authorization.roles_permissions import Permissions
from dojo.finding.queries import get_authorized_findings
from dojo.models import Finding, Product, Product_Type, Test
from dojo.product.queries import get_authorized_products

from .base import ApiV3TestCase

_FANOUT = 30
_PAGE = 10


class _CursorWalkMixin:

    """Follow ``next`` cursors to exhaustion, asserting the forward-only envelope invariants."""

    def _follow(self, next_url: str) -> dict:
        parts = urlsplit(next_url)
        path = parts.path + (f"?{parts.query}" if parts.query else "")
        response = self.client.get(path)
        self.assertEqual(200, response.status_code, response.content[:500])
        return json.loads(response.content)

    def _walk(self, resource: str, params: dict) -> tuple[list[int], int]:
        """Walk every cursor page; return (collected ids in page order, page count)."""
        limit = int(params["limit"])
        body = self.get_json(resource, data={**params, "pagination": "cursor"})
        collected: list[int] = []
        pages = 0
        while True:
            pages += 1
            # Every cursor page: count null, previous null (forward-only, GitLab-style).
            self.assertIsNone(body["count"], f"page {pages} count not null")
            self.assertIsNone(body["previous"], f"page {pages} previous not null")
            collected.extend(row["id"] for row in body["results"])
            if body["next"] is None:
                break
            # A non-final page is exactly full.
            self.assertEqual(limit, len(body["results"]), f"non-final page {pages} not full")
            body = self._follow(body["next"])
        return collected, pages


class TestApiV3CursorFindingsWalk(_CursorWalkMixin, ApiV3TestCase):

    def setUp(self):
        super().setUp()
        test = Test.objects.first()
        self.new_ids = [
            Finding.objects.create(
                title=f"cursor walk {i}", severity="High", numerical_severity="S1",
                description="x", test=test, reporter=self.admin, active=True, verified=(i % 2 == 0),
            ).pk
            for i in range(_FANOUT)
        ]
        # Give the new rows distinct, deliberately shuffled created/updated (via .update() so the
        # auto_now/auto_now_add fields are bypassed) so ordering by created/updated is genuinely
        # different from ordering by id.
        base = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
        for offset, pk in enumerate(self.new_ids):
            created = base + datetime.timedelta(minutes=_FANOUT - offset)  # decreasing vs id
            updated = base + datetime.timedelta(minutes=offset)            # increasing vs id
            Finding.objects.filter(pk=pk).update(created=created, updated=updated)

    def _expected(self, *order: str) -> list[int]:
        qs = get_authorized_findings(Permissions.Finding_View, user=self.admin)
        return list(qs.order_by(*order).values_list("id", flat=True))

    def test_full_walk_visits_every_id_exactly_once(self):
        expected = self._expected("id")
        collected, pages = self._walk("findings", {"limit": _PAGE})
        self.assertEqual(expected, collected)                     # default cursor order = id asc
        self.assertEqual(len(collected), len(set(collected)))     # no id twice
        self.assertEqual(-(-len(expected) // _PAGE), pages)       # ceil(total/page) pages

    def test_default_cursor_ordering_is_id_asc(self):
        body = self.get_json("findings", data={"pagination": "cursor", "limit": 250})
        ids = [r["id"] for r in body["results"]]
        self.assertEqual(sorted(ids), ids)

    def test_walk_o_created_ascending(self):
        collected, _ = self._walk("findings", {"limit": _PAGE, "o": "created"})
        self.assertEqual(self._expected("created", "id"), collected)

    def test_walk_o_updated_descending(self):
        collected, _ = self._walk("findings", {"limit": _PAGE, "o": "-updated"})
        self.assertEqual(self._expected("-updated", "-id"), collected)

    def test_walk_o_id_descending(self):
        collected, _ = self._walk("findings", {"limit": _PAGE, "o": "-id"})
        self.assertEqual(self._expected("-id"), collected)

    def test_non_keyset_ordering_is_400(self):
        # title is a valid offset-mode ordering, but not keyset-safe -> 400 in cursor mode.
        self.get_json("findings", data={"pagination": "cursor", "o": "title"}, expected=400)
        # severity (a computed ordering) is likewise rejected.
        self.get_json("findings", data={"pagination": "cursor", "o": "severity"}, expected=400)

    def test_multi_field_ordering_is_400(self):
        self.get_json("findings", data={"pagination": "cursor", "o": "created,id"}, expected=400)


class TestApiV3CursorTamper(ApiV3TestCase):

    def _problem(self, params: dict):
        response = self.client.get(self.v3_url("findings"), params)
        self.assertEqual(400, response.status_code, response.content[:300])
        self.assertEqual("application/problem+json", response["Content-Type"])
        body = json.loads(response.content)
        self.assertTrue(body["type"].endswith("/errors/pagination"), body["type"])
        return body

    def test_garbage_cursor_is_400(self):
        self._problem({"pagination": "cursor", "cursor": "not-a-real-cursor"})

    def test_tampered_cursor_is_400(self):
        first = self.get_json("findings", data={"pagination": "cursor", "limit": 1})
        self.assertIsNotNone(first["next"])
        cursor = dict(x.split("=", 1) for x in urlsplit(first["next"]).query.split("&"))["cursor"]
        # Flip the final character of the (url-decoded) token to break the signature.
        cursor = unquote(cursor)
        tampered = cursor[:-1] + ("A" if cursor[-1] != "A" else "B")
        self._problem({"pagination": "cursor", "cursor": tampered})

    def test_cursor_from_a_different_ordering_is_400(self):
        # Mint a cursor under o=created, then present it under o=-updated -> ordering mismatch 400.
        first = self.get_json("findings", data={"pagination": "cursor", "limit": 1, "o": "created"})
        self.assertIsNotNone(first["next"])
        cursor = unquote(dict(x.split("=", 1) for x in urlsplit(first["next"]).query.split("&"))["cursor"])
        self._problem({"pagination": "cursor", "o": "-updated", "cursor": cursor})


class TestApiV3CursorComposition(_CursorWalkMixin, ApiV3TestCase):

    def setUp(self):
        super().setUp()
        test = Test.objects.first()
        # A distinctive severity subset to prove the filter composes with the keyset walk.
        self.low_ids = [
            Finding.objects.create(
                title=f"cursor low {i}", severity="Low", numerical_severity="S3",
                description="x", test=test, reporter=self.admin, active=True, verified=False,
            ).pk
            for i in range(_FANOUT)
        ]

    def test_cursor_plus_severity_filter_walks_only_matching_rows(self):
        collected, _ = self._walk("findings", {"limit": _PAGE, "severity": "Low"})
        qs = get_authorized_findings(Permissions.Finding_View, user=self.admin).filter(severity="Low")
        self.assertEqual(list(qs.order_by("id").values_list("id", flat=True)), collected)
        self.assertTrue(set(self.low_ids).issubset(collected))

    def test_cursor_plus_include_counts_keeps_count_null(self):
        body = self.get_json("findings", data={"pagination": "cursor", "include": "counts", "limit": 5})
        self.assertIsNone(body["count"])
        counts = body["meta"]["counts"]
        for key in ("total", "active", "verified", "duplicate", "severity"):
            self.assertIn(key, counts)
        self.assertGreaterEqual(counts["severity"]["Low"], _FANOUT)

    def test_cursor_plus_fields_projects_rows(self):
        body = self.get_json("findings", data={"pagination": "cursor", "fields": "id,title", "limit": 5})
        self.assertIsNone(body["count"])
        for row in body["results"]:
            self.assertEqual({"id", "title"}, set(row))

    def test_cursor_plus_expand_inlines_slim(self):
        body = self.get_json("findings", data={"pagination": "cursor", "expand": "test.engagement", "limit": 5})
        self.assertIsNone(body["count"])
        row = body["results"][0]
        self.assertIn("test_type", row["test"])
        self.assertIn("engagement", row["test"])


class TestApiV3CursorQueryCost(ApiV3TestCase):

    """Cursor mode issues a constant number of queries per page -- one fewer than offset (no COUNT)."""

    # Offset mode is 7 queries (capped count + rows + tags/vulnerability_id_set/finding_cwe_set
    # prefetches); cursor drops the count query -> exactly 6, constant per page regardless of
    # row/page count. (Was 4; +2 for the FindingSlim vulnerability_ids/cwes prefetches added
    # alongside tags -- fixed in-batch prefetches, not per-row.)
    EXPECTED_CURSOR_QUERIES = 6

    def setUp(self):
        super().setUp()
        test = Test.objects.first()
        Finding.objects.bulk_create([
            Finding(title=f"cursor qcount {i}", severity="High", numerical_severity="S1",
                    description="x", test=test, reporter=self.admin, active=True, verified=False)
            for i in range(_FANOUT)
        ])

    def _count_queries(self, params: dict) -> tuple[int, dict]:
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(self.v3_url("findings"), params)
            self.assertEqual(200, response.status_code, response.content[:500])
        return len(ctx.captured_queries), json.loads(response.content)

    def test_cursor_is_one_fewer_query_than_offset(self):
        offset_q, _ = self._count_queries({"limit": _PAGE})
        cursor_q, body = self._count_queries({"pagination": "cursor", "limit": _PAGE})
        # No COUNT query in cursor mode -> exactly one fewer than offset (which counts + estimates).
        self.assertEqual(offset_q - 1, cursor_q, f"offset={offset_q} cursor={cursor_q}")
        self.assertEqual(self.EXPECTED_CURSOR_QUERIES, cursor_q)
        # Page 2 (following the cursor) costs the same as page 1: constant per page.
        page2_q, _ = self._count_queries(
            {"pagination": "cursor", "limit": _PAGE, "cursor": _cursor_of(body)},
        )
        self.assertEqual(cursor_q, page2_q, f"page1={cursor_q} page2={page2_q}")


class TestApiV3CursorAssetsWalk(_CursorWalkMixin, ApiV3TestCase):

    """A non-finding resource cursor walk proves the mode is uniform across the list routes (I5)."""

    def setUp(self):
        super().setUp()
        prod_type = Product_Type.objects.first()
        for i in range(_FANOUT):
            Product.objects.create(name=f"cursor asset {i}", description="x", prod_type=prod_type)

    def test_assets_full_walk(self):
        expected = list(
            get_authorized_products(Permissions.Product_View, user=self.admin)
            .order_by("id").values_list("id", flat=True),
        )
        collected, pages = self._walk("assets", {"limit": 5})
        self.assertEqual(expected, collected)
        self.assertEqual(len(collected), len(set(collected)))
        self.assertEqual(-(-len(expected) // 5), pages)


class TestApiV3CursorPerResourceOrderings(ApiV3TestCase):

    """The keyset-safe ordering set is derived per FilterSpec (id always; created/updated if declared)."""

    def test_users_allow_only_id(self):
        # users declare id/username/date_joined/last_login orderings, but only `id` is keyset-safe.
        self.get_json("users", data={"pagination": "cursor", "limit": 5})                    # id -> ok
        self.get_json("users", data={"pagination": "cursor", "o": "created"}, expected=400)  # not keyset-safe
        self.get_json("users", data={"pagination": "cursor", "o": "username"}, expected=400)

    def test_organizations_allow_created_updated(self):
        for order in ("id", "created", "-updated"):
            self.get_json("organizations", data={"pagination": "cursor", "o": order, "limit": 5})
        self.get_json("organizations", data={"pagination": "cursor", "o": "name"}, expected=400)


class TestApiV3CursorSubResourceUnsupported(ApiV3TestCase):

    """Parent-scoped edge sub-resource lists have no FilterSpec -> cursor mode is a 400 there."""

    def test_finding_locations_cursor_is_400(self):
        finding_id = Finding.objects.first().pk
        response = self.client.get(
            self.v3_url(f"findings/{finding_id}/locations"), {"pagination": "cursor"},
        )
        self.assertEqual(400, response.status_code, response.content[:300])
        self.assertEqual("application/problem+json", response["Content-Type"])


def _cursor_of(body: dict) -> str:
    query = urlsplit(body["next"]).query
    raw = dict(x.split("=", 1) for x in query.split("&"))["cursor"]
    return unquote(raw)
