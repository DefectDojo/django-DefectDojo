"""
Pagination envelope for API v3 (D4 / §4.3).

One closed envelope ``{count, next, previous, results, meta?}`` (I1) with two opt-in modes selected
by ``?pagination=``:

**offset** (the default) -- ``limit``/``offset`` with a hybrid exact -> planner-estimate ``count``:
  1. Capped exact count via ``qs.order_by()[:CAP+1].count()`` (bounded cost).
  2. ``<= CAP`` -> ``count`` is exact.
  3. ``== CAP+1`` -> ``count`` is the Postgres planner's row estimate for the same filtered
     queryset (``EXPLAIN (FORMAT JSON)`` -> ``Plan Rows``), clamped to ``max(estimate, CAP+1)``;
     the envelope gains ``meta.count_exact = false``.
  Never a full ``COUNT(*)`` on unbounded tables, never a second PK-prefetch phase.

**cursor** (``?pagination=cursor``) -- forward-only keyset pagination for export/sync consumers
(GitLab precedent: same endpoints, opt-in keyset). Same envelope with ``count: null`` and
``previous: null`` (forward-only -- there is no backward cursor); ``next`` is the same URL carrying
an opaque, signed ``cursor=`` token. Sorting is restricted to keyset-safe orderings (``id``,
``created``, ``updated`` -- each +/- direction, whichever the resource's ``FilterSpec`` declares),
always with a deterministic ``id`` tiebreaker appended; the default is ``id`` ascending. The page is
read as ``limit + 1`` rows to detect a next page without any ``COUNT`` query. Cursors are
tamper-proof (``django.core.signing`` under a dedicated salt) and carry only the ordering + the last
row's key values -- filters are NOT encoded, so changing a filter mid-walk is the client's own
foot-gun (documented on the docs page). A tampered / undecodable / ordering-mismatched cursor is a
400 problem+json (pagination error type). Keyset columns (``id``/``created``/``updated``) are the PK
and the model's auto timestamps, so they are non-null and the tuple comparison needs no NULL handling.
"""
from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING
from urllib.parse import urlencode, urlparse, urlunparse

from django.conf import settings
from django.core import signing
from django.db.models import Q

from dojo.api_v3.errors import pagination_problem

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.db.models import QuerySet
    from django.http import HttpRequest

    from dojo.api_v3.filtering import FilterSpec

logger = logging.getLogger(__name__)

# Cursor signing salt (D4/§4.3): dedicated so a cursor can never be confused with any other signed
# blob, and so only cursors minted by this module validate.
CURSOR_SALT = "dojo.api_v3.cursor"
# Keyset-safe ordering fields (D4). A resource permits the subset its FilterSpec declares; ``id`` is
# always present and doubles as the deterministic tiebreaker.
_KEYSET_FIELDS = ("id", "created", "updated")


def _pagination_mode(request: HttpRequest) -> str:
    """Return the requested pagination mode; reject an unknown mode with 400 problem+json."""
    mode = request.GET.get("pagination", "offset")
    if mode not in {"offset", "cursor"}:
        msg = f"unknown pagination mode '{mode}'"
        raise pagination_problem(msg)
    return mode


def _parse_limit(request: HttpRequest) -> int:
    """Return the clamped page size; reject a malformed/out-of-range ``limit`` with 400."""
    default_limit = settings.API_V3_PAGE_LIMIT_DEFAULT
    max_limit = settings.API_V3_PAGE_LIMIT_MAX
    try:
        limit = int(request.GET.get("limit", default_limit))
    except (TypeError, ValueError):
        msg = "limit must be an integer"
        raise pagination_problem(msg)
    if limit < 1:
        msg = "limit must be >= 1"
        raise pagination_problem(msg)
    return min(limit, max_limit)


def parse_pagination(request: HttpRequest) -> tuple[int, int]:
    """Offset-mode ``(limit, offset)``; malformed values -> 400. (Cursor mode is handled in ``paginate``.)"""
    limit = _parse_limit(request)
    try:
        offset = int(request.GET.get("offset", 0))
    except (TypeError, ValueError):
        msg = "offset must be an integer"
        raise pagination_problem(msg)
    if offset < 0:
        msg = "offset must be >= 0"
        raise pagination_problem(msg)
    return limit, offset


def _planner_estimate(qs: QuerySet) -> int | None:
    """Postgres planner row estimate for the filtered queryset (best effort)."""
    try:
        raw = qs.order_by().explain(format="json")
        data = json.loads(raw) if isinstance(raw, str) else raw
        return int(data[0]["Plan"]["Plan Rows"])
    except Exception:
        logger.warning("api_v3 pagination: planner estimate failed; falling back to CAP+1", exc_info=True)
        return None


def compute_count(count_qs: QuerySet, cap: int | None = None) -> tuple[int, bool]:
    """Return ``(count, count_exact)`` per the hybrid strategy above."""
    if cap is None:
        cap = settings.API_V3_COUNT_CAP
    capped = count_qs.order_by()[: cap + 1].count()
    if capped <= cap:
        return capped, True
    estimate = _planner_estimate(count_qs)
    if estimate is None:
        return cap + 1, False
    return max(estimate, cap + 1), False


def _page_url(request: HttpRequest, limit: int, offset: int) -> str:
    parsed = urlparse(request.build_absolute_uri())
    params = {}
    # Preserve every existing query param (filters, expand, include, o, ...) except limit/offset.
    for key in request.GET:
        if key in {"limit", "offset"}:
            continue
        values = request.GET.getlist(key)
        params[key] = values if len(values) > 1 else values[0]
    params["limit"] = limit
    params["offset"] = offset
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


# --- Cursor (keyset) mode ---------------------------------------------------------------------

def _keyset_orderings(spec: FilterSpec) -> list[str]:
    """The keyset-safe ordering keys this resource permits (``id`` always; ``created``/``updated`` if declared)."""
    return [name for name in _KEYSET_FIELDS if name in spec.orderings]


def _split_token(token: str) -> tuple[str, bool]:
    """Split an ordering token like ``-created`` into ``("created", desc=True)``."""
    desc = token.startswith("-")
    return (token[1:] if desc else token), desc


def _resolve_cursor_ordering(request: HttpRequest, spec: FilterSpec) -> str:
    """
    Resolve ``o=`` to a single keyset-safe ordering token (e.g. ``created`` / ``-id``); default
    ``id`` ascending. A multi-field or non-keyset-safe ordering is a 400 (pagination error type).
    """
    allowed = _keyset_orderings(spec)
    raw = (request.GET.get("o") or "").strip()
    if not raw:
        return "id"
    tokens = [t.strip() for t in raw.split(",") if t.strip()]
    if len(tokens) != 1:
        msg = f"cursor pagination allows a single keyset-safe ordering (one of: {', '.join(allowed)})"
        raise pagination_problem(msg)
    key, _ = _split_token(tokens[0])
    if key not in allowed:
        msg = f"'{key}' is not a keyset-safe ordering for cursor pagination (allowed: {', '.join(allowed)})"
        raise pagination_problem(msg)
    return tokens[0]


def _cursor_order_by(token: str, spec: FilterSpec) -> list[str]:
    """The ``order_by`` args for a cursor token: the keyset field then the ``id`` tiebreaker (same direction)."""
    key, desc = _split_token(token)
    sign = "-" if desc else ""
    if key == "id":
        return [f"{sign}id"]
    return [f"{sign}{spec.orderings[key]}", f"{sign}id"]


def _encode_cursor(token: str, row: object, spec: FilterSpec) -> str:
    """Sign a cursor carrying the ordering token + the last row's key value(s) (D4)."""
    key, _ = _split_token(token)
    payload: dict = {"o": token, "id": row.pk}
    if key != "id":
        value = getattr(row, spec.orderings[key])
        # Datetimes aren't JSON-serializable; store ISO-8601 (Django parses it back on filter). A
        # NULL keyset value is stored as JSON null and handled explicitly on the next page.
        payload["v"] = value.isoformat() if hasattr(value, "isoformat") else value
    return signing.dumps(payload, salt=CURSOR_SALT)


def _decode_cursor(raw: str, token: str) -> dict:
    """Verify + decode a cursor; a tampered/undecodable or ordering-mismatched cursor is a 400."""
    try:
        payload = signing.loads(raw, salt=CURSOR_SALT)
    except signing.BadSignature:
        msg = "invalid or tampered pagination cursor"
        raise pagination_problem(msg)
    if not isinstance(payload, dict) or payload.get("o") != token:
        msg = "pagination cursor does not match the requested ordering"
        raise pagination_problem(msg)
    return payload


def _keyset_filter(payload: dict, token: str, spec: FilterSpec) -> Q:
    """
    Keyset predicate as a tuple comparison: ``(key > last) OR (key = last AND id > last_id)``,
    inverted for a descending walk. For an ``id`` ordering there is no separate tiebreaker.

    NULL-aware because the timestamp columns are nullable in practice (e.g. legacy findings have a
    NULL ``updated``, and the model metadata cannot be trusted for it). Django/Postgres place NULLs
    LAST for an ascending sort and FIRST for a descending one; the predicate is built to match that
    placement so the keyset never skips or repeats a NULL row.
    """
    key, desc = _split_token(token)
    op = "lt" if desc else "gt"
    last_id = payload["id"]
    if key == "id":
        return Q(**{f"id__{op}": last_id})

    path = spec.orderings[key]
    last_value = payload.get("v")
    id_tie = Q(**{f"id__{op}": last_id})
    is_null = Q(**{f"{path}__isnull": True})
    not_null = Q(**{f"{path}__isnull": False})

    if last_value is None:
        # The last row's key was NULL.
        #  - ASC (NULLS LAST): we are in the trailing NULL group; only NULLs with a larger id remain.
        #  - DESC (NULLS FIRST): we are in the leading NULL group; remaining NULLs (smaller id) then
        #    every non-NULL row follow.
        null_tail = is_null & id_tie
        return (null_tail | not_null) if desc else null_tail

    strict = Q(**{f"{path}__{op}": last_value})
    tie = Q(**{path: last_value}) & id_tie
    if desc:
        # DESC (NULLS FIRST): the NULL group is already behind us, so only non-NULL rows remain.
        return strict | tie
    # ASC (NULLS LAST): after the non-NULL group come the trailing NULL rows.
    return strict | tie | is_null


def _cursor_url(request: HttpRequest, cursor: str) -> str:
    parsed = urlparse(request.build_absolute_uri())
    params = {}
    # Preserve filters/expand/include/fields/o/limit/pagination; drop offset + any stale cursor.
    for key in request.GET:
        if key in {"offset", "cursor"}:
            continue
        values = request.GET.getlist(key)
        params[key] = values if len(values) > 1 else values[0]
    params["cursor"] = cursor
    return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


def _paginate_cursor(
    request: HttpRequest,
    *,
    page_qs: QuerySet,
    serialize: Callable[[object], dict],
    spec: FilterSpec,
) -> dict:
    limit = _parse_limit(request)
    token = _resolve_cursor_ordering(request, spec)

    qs = page_qs.order_by(*_cursor_order_by(token, spec))
    raw_cursor = request.GET.get("cursor")
    if raw_cursor:
        qs = qs.filter(_keyset_filter(_decode_cursor(raw_cursor, token), token, spec))

    # limit + 1 rows detect a next page without a COUNT query (forward-only keyset).
    rows = list(qs[: limit + 1])
    has_next = len(rows) > limit
    rows = rows[:limit]
    results = [serialize(row) for row in rows]

    next_url = _cursor_url(request, _encode_cursor(token, rows[-1], spec)) if (has_next and rows) else None
    return {
        "count": None,      # cursor mode never counts (D4)
        "next": next_url,
        "previous": None,   # forward-only, GitLab-style (D4)
        "results": results,
    }


def paginate(
    request: HttpRequest,
    *,
    count_qs: QuerySet,
    page_qs: QuerySet,
    serialize: Callable[[object], dict],
    cap: int | None = None,
    filter_spec: FilterSpec | None = None,
) -> dict:
    """
    Build the pagination envelope. ``count_qs`` is the clean filtered/authorized queryset used for
    counting (offset mode) and ``?include=`` aggregates; ``page_qs`` is the
    (select_related/annotated/prefetched/expand-planned/deferred) queryset the page rows are read
    from. Both must derive from the same filtered, authorized base.

    ``?pagination=cursor`` selects forward-only keyset mode, which needs the resource's
    ``filter_spec`` to derive the keyset-safe orderings and build the keyset predicate. Endpoints
    without a ``filter_spec`` (parent-scoped sub-resource / edge lists) support offset mode only.
    """
    if _pagination_mode(request) == "cursor":
        if filter_spec is None:
            msg = "cursor pagination is not available for this endpoint"
            raise pagination_problem(msg)
        return _paginate_cursor(request, page_qs=page_qs, serialize=serialize, spec=filter_spec)

    limit, offset = parse_pagination(request)
    count, count_exact = compute_count(count_qs, cap)

    rows = list(page_qs[offset : offset + limit])
    results = [serialize(row) for row in rows]

    # For an exact count, "next" follows the count; for an estimate the count may be wrong near the
    # end, so base "next" on whether a full page came back (client tolerates an empty final page).
    has_next = (offset + limit < count) if count_exact else (len(rows) == limit)
    has_previous = offset > 0

    envelope: dict = {
        "count": count,
        "next": _page_url(request, limit, offset + limit) if has_next else None,
        "previous": _page_url(request, limit, max(0, offset - limit)) if has_previous else None,
        "results": results,
    }
    meta: dict = {}
    if not count_exact:
        meta["count_exact"] = False
    if meta:
        envelope["meta"] = meta
    return envelope
