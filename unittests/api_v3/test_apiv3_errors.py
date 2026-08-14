"""
Error-contract sweep for API v3 (D9 / §4.10, §6 OS2 / I9).

Every v3-raised failure path must return an RFC 9457 ``application/problem+json`` body with the
correct ``type`` URI, ``status`` and ``title``. This module asserts that for each failure kind.
(Django's default 500 handler is out of scope -- only v3-raised paths.)
"""
from __future__ import annotations

from typing import ClassVar

from django.test import SimpleTestCase, override_settings
from ninja import Schema

from dojo.api_v3.errors import ProblemDetail
from dojo.api_v3.expand import ExpandRel, plan
from dojo.models import Finding

from .base import ApiV3TestCase


class TestApiV3ErrorContract(ApiV3TestCase):

    def _assert_problem(self, path, *, status, type_suffix, client=None, data=None):
        client = client or self.client
        response = client.get(self.v3_url(path), data or {})
        self.assertEqual(status, response.status_code, response.content[:500])
        self.assertEqual("application/problem+json", response["Content-Type"], response.content[:200])
        body = response.json()
        self.assertEqual(status, body["status"])
        self.assertIn("title", body)
        self.assertTrue(
            body["type"].endswith("#error-" + type_suffix),
            f"expected type ...#error-{type_suffix}, got {body['type']}",
        )
        return body

    # --- 400: expand -----------------------------------------------------------------------
    def test_unknown_expand_relation_is_problem(self):
        self._assert_problem("findings", status=400, type_suffix="expand", data={"expand": "nope"})

    def test_expand_budget_exceeded_is_problem(self):
        with override_settings(API_V3_EXPAND_BUDGET=1):
            self._assert_problem(
                "findings", status=400, type_suffix="expand",
                data={"expand": "test.engagement,reporter"},
            )

    def test_expand_further_on_special_is_problem(self):
        # `locations` is a leaf special renderer; drilling into it is rejected.
        self._assert_problem(
            "findings", status=400, type_suffix="expand", data={"expand": "locations.location"},
        )

    # --- 400: fields -----------------------------------------------------------------------
    def test_unknown_field_is_problem(self):
        self._assert_problem("findings", status=400, type_suffix="fields", data={"fields": "id,nope"})

    # --- 400: filter -----------------------------------------------------------------------
    def test_unknown_filter_param_is_problem(self):
        self._assert_problem("findings", status=400, type_suffix="filter", data={"not_a_filter": "x"})

    def test_invalid_filter_value_is_problem(self):
        # `cwe` is numeric; a non-numeric value fails django-filter validation.
        self._assert_problem("findings", status=400, type_suffix="filter", data={"cwe": "abc"})

    def test_unknown_ordering_is_problem(self):
        self._assert_problem("findings", status=400, type_suffix="filter", data={"o": "nope"})

    # --- 400: pagination -------------------------------------------------------------------
    def test_bad_limit_is_problem(self):
        self._assert_problem("findings", status=400, type_suffix="pagination", data={"limit": "-1"})

    def test_non_integer_limit_is_problem(self):
        self._assert_problem("findings", status=400, type_suffix="pagination", data={"limit": "abc"})

    def test_unknown_pagination_mode_is_problem(self):
        self._assert_problem(
            "findings", status=400, type_suffix="pagination", data={"pagination": "bogus"},
        )

    def test_cursor_non_keyset_ordering_is_problem(self):
        # Cursor mode is implemented; a non-keyset-safe ordering is a pagination problem.
        self._assert_problem(
            "findings", status=400, type_suffix="pagination",
            data={"pagination": "cursor", "o": "title"},
        )

    # --- 401 / 404 -------------------------------------------------------------------------
    def test_anonymous_is_401_problem(self):
        self._assert_problem(
            "findings", status=401, type_suffix="unauthorized", client=self.anonymous_client(),
        )

    def test_unknown_or_unauthorized_detail_is_404_problem(self):
        self._assert_problem("findings/99999999", status=404, type_suffix="not-found")


class _CyclicSchema(Schema):

    """A synthetic self-referential schema used only to exercise the expand cycle guard."""

    django_model: ClassVar = Finding
    EXPANDABLE: ClassVar[dict] = {}

    id: int


_CyclicSchema.EXPANDABLE = {"loop": ExpandRel(attr="x", path="x", schema=_CyclicSchema)}


class TestApiV3ExpandCycleGuard(SimpleTestCase):

    """
    Kernel-internal unit test (§6 preamble).

    The cycle guard is not reachable via the OS2 findings registry (it has no cyclic relation),
    so it is tested directly against ``plan()``.
    """

    def test_cycle_is_rejected(self):
        with self.assertRaises(ProblemDetail) as ctx:
            plan(_CyclicSchema, "loop")
        self.assertEqual(400, ctx.exception.status)
        self.assertEqual("expand", ctx.exception.error_type)
        self.assertIn("cycle", ctx.exception.detail.lower())
