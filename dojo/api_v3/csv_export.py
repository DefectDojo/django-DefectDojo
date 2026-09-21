"""
CSV export kernel for API v3 (D6 / §4.15).

D6 is "one filter contract, many projections". The list is one projection; CSV export is another:
``GET /<resource>/export.csv`` takes the **identical** filter contract as the list (``filters``,
``o=``, ``q=``, ``?fields=`` including the detail opt-up) and streams the **whole filtered,
authorized set** as CSV. There is no pagination -- the export is the whole set -- so the pagination /
expand / include reserved params are **not** applicable and are rejected with a 400 problem+json
(``reject_export_params``); keeping that rejection here keeps the reserved-param handling coherent
with the list (§4.9).

This module is **resource-agnostic** (no resource imports): the route builds the same
filtered/authorized queryset + ``ListFieldPlan`` it builds for the list, then hands them here. The
columns are derived generically from the serialization schema (never a hand-built per-resource column
list, I5):

- a ``Ref`` field (``{id, name}``) -> two columns ``<key>_id`` / ``<key>_name``;
- a ``LocationRef`` field (``{id, name, type}``) -> three columns ``<key>_id`` / ``<key>_name`` /
  ``<key>_type``;
- a list field (e.g. ``tags``) -> one semicolon-joined column;
- everything else -> one column, datetimes rendered ISO-8601 ``Z`` and dates ``YYYY-MM-DD`` (§4.11).

Row values come from the same ``serialize_list_row`` the list uses (so the CSV never diverges from
the JSON shape), then flattened. The response is a ``StreamingHttpResponse`` written by a
``csv.writer`` over ``queryset.iterator(chunk_size=...)`` so memory is bounded and the query count is
independent of the row count (a fixed, small number of prefetch batches per chunk -- pinned by an
``assertNumQueries`` test).

**Cap (never silent truncation, I-style honesty):** the filtered count is measured with the shared
capped-count helper; if it exceeds ``settings.API_V3_EXPORT_MAX_ROWS`` the request is a 400 telling
the client to narrow the filter, rather than exporting a truncated file.

**CSV-injection hardening (this is a security product):** a cell whose text starts with ``= + - @``
or a TAB is prefixed with a single quote -- the standard spreadsheet formula-injection defense.
"""
from __future__ import annotations

import csv
import datetime
import types
import typing
from dataclasses import dataclass
from typing import TYPE_CHECKING

from django.conf import settings
from django.http import StreamingHttpResponse

from dojo.api_v3.errors import ProblemDetail
from dojo.api_v3.expand import serialize_list_row
from dojo.api_v3.pagination import compute_count
from dojo.api_v3.refs import LocationRef, Ref

if TYPE_CHECKING:
    from django.db.models import QuerySet
    from django.http import HttpRequest

    from dojo.api_v3.expand import ListFieldPlan

# Rows are streamed from a server-side chunked iterator; a chunk drives one batch of prefetch
# queries. Test-sized data fits in one chunk (constant query count); a 100k export is <= 50 batches.
_ITERATOR_CHUNK_SIZE = 2000

# Leading characters a spreadsheet may interpret as a formula -- prefix such a cell with a quote.
_INJECTION_PREFIXES = frozenset("=+-@\t")

# Reserved params that do not apply to an export (the export is the whole filtered set): pagination
# (limit/offset/pagination/cursor), and the projection add-ons expand/include. ``fields``/``o``/``q``
# are accepted (identical filter contract as the list, §4.15).
_DISALLOWED_PARAMS = ("cursor", "expand", "include", "limit", "offset", "pagination")


def export_problem(detail: str) -> ProblemDetail:
    """A 400 problem+json for an invalid export request (new ``type`` URI, closed contract -- I9)."""
    return ProblemDetail(status=400, error_type="export", title="Invalid export request", detail=detail)


def reject_export_params(request: HttpRequest) -> None:
    """Reject pagination/expand/include params on an export (not applicable) -- 400 problem+json."""
    present = [p for p in _DISALLOWED_PARAMS if p in request.GET]
    if present:
        msg = (
            f"parameter(s) {', '.join(present)} are not applicable to CSV export -- the export "
            f"covers the whole filtered set (use filters, o=, q= and fields= only)"
        )
        raise export_problem(msg)


# --- Column derivation (generic; driven by the serialization schema) --------------------------

@dataclass(frozen=True)
class _Column:

    """One flat CSV column: its header, the source row key, and how to extract the value."""

    header: str
    field: str
    part: str  # "scalar" | "list" | "ref_id" | "ref_name" | "ref_type"


def _core_type(annotation: object) -> object:
    """Strip ``X | None`` / ``Optional[X]`` down to ``X`` (leave a genuine multi-member union alone)."""
    if typing.get_origin(annotation) in {typing.Union, types.UnionType}:
        members = [a for a in typing.get_args(annotation) if a is not type(None)]
        if len(members) == 1:
            return members[0]
    return annotation


def _column_kind(annotation: object) -> str:
    """Classify a schema field's annotation into a flattening kind (resource-agnostic)."""
    core = _core_type(annotation)
    if typing.get_origin(core) in {list, tuple, set, frozenset}:
        return "list"
    if isinstance(core, type) and issubclass(core, LocationRef):
        return "location_ref"  # LocationRef adds ``type`` -> three columns
    if isinstance(core, type) and issubclass(core, Ref):
        return "ref"
    return "scalar"


def build_columns(plan: ListFieldPlan) -> list[_Column]:
    """
    Derive the ordered flat column list from the plan's serialization schema, restricted to the
    requested ``?fields=`` projection (``id`` always included). Order = schema declaration order,
    each ref expanded to its id/name(/type) sub-columns; identical whether the filtered set has rows
    or not, so a zero-row export still emits a full header row.
    """
    schema = plan.serialization_schema
    requested = plan.requested
    columns: list[_Column] = []
    for name, info in schema.model_fields.items():
        if requested is not None and name not in requested:
            continue
        kind = _column_kind(info.annotation)
        if kind == "location_ref":
            columns += [
                _Column(f"{name}_id", name, "ref_id"),
                _Column(f"{name}_name", name, "ref_name"),
                _Column(f"{name}_type", name, "ref_type"),
            ]
        elif kind == "ref":
            columns += [
                _Column(f"{name}_id", name, "ref_id"),
                _Column(f"{name}_name", name, "ref_name"),
            ]
        else:  # "list" or "scalar" -> one column
            columns.append(_Column(name, name, kind))
    return columns


# --- Value formatting -------------------------------------------------------------------------

def _format_scalar(value: object) -> str:
    """Render one scalar for CSV: ISO-8601 ``Z`` datetimes, ``YYYY-MM-DD`` dates, lowercase bools."""
    if value is None:
        return ""
    if isinstance(value, bool):  # before int: bool is an int subclass
        return "true" if value else "false"
    if isinstance(value, datetime.datetime):
        if value.tzinfo is not None:
            value = value.astimezone(datetime.UTC)
        text = value.isoformat()
        return text[:-6] + "Z" if text.endswith("+00:00") else text
    if isinstance(value, datetime.date):
        return value.isoformat()
    return str(value)


def _harden(cell: str) -> str:
    """CSV-injection defense: quote-prefix a cell that starts with a formula trigger character."""
    if cell and cell[0] in _INJECTION_PREFIXES:
        return "'" + cell
    return cell


def _cell(row: dict, column: _Column) -> str:
    value = row.get(column.field)
    if column.part == "scalar":
        return _harden(_format_scalar(value))
    if column.part == "list":
        return _harden(";".join(_format_scalar(item) for item in (value or [])))
    # ref parts: the row value is a ``{id, name[, type]}`` dict or None
    if not isinstance(value, dict):
        return ""
    key = {"ref_id": "id", "ref_name": "name", "ref_type": "type"}[column.part]
    return _harden(_format_scalar(value.get(key)))


# --- Streaming response builder ---------------------------------------------------------------

class _Echo:

    """A write-only file-like whose ``write`` returns the value, so ``csv.writer`` yields each line."""

    def write(self, value: str) -> str:
        return value


def stream_csv_export(
    request: HttpRequest,
    *,
    resource: str,
    count_qs: QuerySet,
    page_qs: QuerySet,
    plan: ListFieldPlan,
    max_rows: int | None = None,
    chunk_size: int = _ITERATOR_CHUNK_SIZE,
) -> StreamingHttpResponse:
    """
    Guard the request, enforce the row cap, and return a streaming ``text/csv`` attachment.

    ``count_qs`` is the clean filtered/authorized queryset (cap check); ``page_qs`` is the
    select_related/prefetch/annotate/defer'd queryset the rows stream from -- both from the same
    filtered, authorized base, exactly like the list route (§4.15). ``plan`` is the resource's
    already-built ``ListFieldPlan`` (opt-up ``?fields=`` + defer), reused so the CSV columns and row
    values match the list projection.
    """
    reject_export_params(request)

    cap = settings.API_V3_EXPORT_MAX_ROWS if max_rows is None else max_rows
    # compute_count returns count_exact=False iff the (capped) count exceeded ``cap`` -- reuse it as
    # the "over the export cap" signal rather than a full COUNT(*) (§4.3 capped-count helper).
    _, within_cap = compute_count(count_qs, cap=cap)
    if not within_cap:
        msg = (
            f"the filtered result set exceeds the CSV export cap of {cap} rows; narrow the filter "
            f"(add filters or a date range) and retry -- the export is never silently truncated"
        )
        raise export_problem(msg)

    columns = build_columns(plan)

    def rows() -> typing.Iterator[str]:
        writer = csv.writer(_Echo())
        yield writer.writerow([column.header for column in columns])
        for obj in page_qs.iterator(chunk_size=chunk_size):
            data = serialize_list_row(obj, plan, {})
            yield writer.writerow([_cell(data, column) for column in columns])

    response = StreamingHttpResponse(rows(), content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{resource}-export.csv"'
    response["X-API-Status"] = settings.API_V3_STATUS
    return response
