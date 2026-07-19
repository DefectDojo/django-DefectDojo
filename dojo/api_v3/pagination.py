"""
Pagination envelope for API v3 (D4 / §4.3).

One closed envelope ``{count, next, previous, results, meta}`` (I1); offset is the only mode in
alpha. ``?pagination=cursor`` is reserved and rejected with 400 so the param can't be squatted.

Count strategy (hybrid exact -> planner estimate):
  1. Capped exact count via ``qs.order_by()[:CAP+1].count()`` (bounded cost).
  2. ``<= CAP`` -> ``count`` is exact.
  3. ``== CAP+1`` -> ``count`` is the Postgres planner's row estimate for the same filtered
     queryset (``EXPLAIN (FORMAT JSON)`` -> ``Plan Rows``), clamped to ``max(estimate, CAP+1)``;
     the envelope gains ``meta.count_exact = false``.
Never a full ``COUNT(*)`` on unbounded tables, never a second PK-prefetch phase.
"""
from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING
from urllib.parse import urlencode, urlparse, urlunparse

from django.conf import settings

from dojo.api_v3.errors import pagination_problem

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.db.models import QuerySet
    from django.http import HttpRequest

logger = logging.getLogger(__name__)


def parse_pagination(request: HttpRequest) -> tuple[int, int]:
    """Return ``(limit, offset)``; reject cursor mode and malformed values with 400 problem+json."""
    mode = request.GET.get("pagination", "offset")
    if mode == "cursor":
        msg = "cursor pagination not yet available"
        raise pagination_problem(msg)
    if mode != "offset":
        msg = f"unknown pagination mode '{mode}'"
        raise pagination_problem(msg)

    default_limit = settings.API_V3_PAGE_LIMIT_DEFAULT
    max_limit = settings.API_V3_PAGE_LIMIT_MAX
    try:
        limit = int(request.GET.get("limit", default_limit))
    except (TypeError, ValueError):
        msg = "limit must be an integer"
        raise pagination_problem(msg)
    try:
        offset = int(request.GET.get("offset", 0))
    except (TypeError, ValueError):
        msg = "offset must be an integer"
        raise pagination_problem(msg)
    if limit < 1:
        msg = "limit must be >= 1"
        raise pagination_problem(msg)
    if offset < 0:
        msg = "offset must be >= 0"
        raise pagination_problem(msg)
    return min(limit, max_limit), offset


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


def paginate(
    request: HttpRequest,
    *,
    count_qs: QuerySet,
    page_qs: QuerySet,
    serialize: Callable[[object], dict],
    cap: int | None = None,
) -> dict:
    """
    Build the pagination envelope. ``count_qs`` is the clean filtered/authorized queryset used for
    counting; ``page_qs`` is the (select_related/annotated/prefetched/expand-planned) queryset the
    page rows are read from. Both must derive from the same filtered, authorized base.
    """
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
