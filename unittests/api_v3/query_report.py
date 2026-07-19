"""
Query-capture harness for API v3 (§7 of the plan / OS6 verification).

Captures every SQL query a v3 request executes and detects the N+1 signature: the same
*normalized* query shape executed many times within one request. Complements the per-list
``assertNumQueries`` tests (which pin totals) by identifying *which* query repeats when a
regression appears, and by sweeping the whole mounted surface in one place
(``test_apiv3_query_report.py``) so new resources are covered automatically.

Also usable interactively from a shell (``manage.py shell`` + test client) to profile an
endpoint; ``format_report`` renders the capture as markdown.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from django.db import connection
from django.test.utils import CaptureQueriesContext

# Normalization: collapse literals so structurally-identical queries group together.
_NORMALIZERS = (
    (re.compile(r"'(?:[^']|'')*'"), "'?'"),          # string literals
    (re.compile(r"\b\d+(?:\.\d+)?\b"), "N"),          # numeric literals
    (re.compile(r"IN \([^)]*\)", re.IGNORECASE), "IN (...)"),  # IN lists (prefetch batches)
    (re.compile(r"\s+"), " "),                        # whitespace
)

# Shapes that legitimately repeat and are never an N+1 signal.
_IGNORED_SHAPES = (
    re.compile(r"^(SAVEPOINT|RELEASE SAVEPOINT|ROLLBACK TO SAVEPOINT)", re.IGNORECASE),
)


def normalize_sql(sql: str) -> str:
    for pattern, replacement in _NORMALIZERS:
        sql = pattern.sub(replacement, sql)
    return sql.strip()


@dataclass
class EndpointCapture:

    """One request's query profile."""

    label: str
    path: str
    status_code: int
    query_count: int
    result_rows: int | None
    shapes: Counter = field(default_factory=Counter)

    def repeated_shapes(self, threshold: int) -> list[tuple[str, int]]:
        """Normalized shapes executed >= threshold times, excluding known-benign ones."""
        flagged = []
        for shape, count in self.shapes.most_common():
            if count < threshold:
                break
            if any(p.search(shape) for p in _IGNORED_SHAPES):
                continue
            flagged.append((shape, count))
        return flagged


def capture_request(client, label: str, path: str) -> EndpointCapture:
    """Execute a GET through the in-process client and capture its query profile."""
    with CaptureQueriesContext(connection) as ctx:
        response = client.get(path)
    shapes = Counter(normalize_sql(q["sql"]) for q in ctx.captured_queries)
    rows = None
    if response.status_code == 200:
        try:
            body = response.json()
            rows = len(body["results"]) if isinstance(body, dict) and "results" in body else None
        except ValueError:
            rows = None
    return EndpointCapture(
        label=label,
        path=path,
        status_code=response.status_code,
        query_count=len(ctx.captured_queries),
        result_rows=rows,
        shapes=shapes,
    )


def format_report(captures: list[EndpointCapture], threshold: int) -> str:
    """Render captures as a markdown report (written to /tmp by the sweep test)."""
    lines = [
        "# API v3 query report",
        "",
        f"N+1 flag threshold: same normalized query shape >= {threshold}x in one request.",
        "",
        "| endpoint | status | queries | rows | flagged shapes |",
        "|---|---|---:|---:|---|",
    ]
    for cap in captures:
        flagged = cap.repeated_shapes(threshold)
        flag_text = "; ".join(f"{count}x `{shape[:80]}...`" for shape, count in flagged) if flagged else "-"
        lines.append(
            f"| {cap.label} | {cap.status_code} | {cap.query_count} "
            f"| {cap.result_rows if cap.result_rows is not None else '-'} | {flag_text} |",
        )
    lines.append("")
    for cap in captures:
        for shape, count in cap.repeated_shapes(threshold):
            lines += [f"## {cap.label}: {count}x", "", "```sql", shape, "```", ""]
    return "\n".join(lines)
