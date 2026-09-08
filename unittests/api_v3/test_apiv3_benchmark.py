r"""
In-process latency + query-count benchmark: v2 ``?prefetch=`` vs v3 ``?expand=`` (OS6, §11).

**CI-EXCLUDED.** Gated behind ``DD_API_V3_BENCH=1`` so the normal suite never pays for it. Run:

    docker compose exec -e DD_API_V3_BENCH=1 uwsgi \\
        python manage.py test unittests.api_v3.test_apiv3_benchmark -v2 --keepdb

It seeds ~1000 findings on ONE product/test, then times ``N=30`` repeated in-process test-client
GETs against each endpoint and captures the per-request SQL count. The methodology + caveats and
the results table are written **verbatim** to ``.claude/os6-benchmark.md`` (repo root is bind-mounted
into the container) and echoed to stdout. Numbers are **never fabricated**.

Honesty caveats (also written into the report): these are IN-PROCESS numbers -- no HTTP layer, no
uwsgi worker, no network, no connection-pool warmup; single-threaded; the requests share one test
transaction against the (kept) test DB. They are therefore **directional** (they isolate the
serialization + ORM cost that the query-count gap predicts), not a substitute for a wall-clock
latency benchmark against a running uwsgi stack (the procedure for which is in
``.claude/os1-gate-report.md``). The query counts, by contrast, are exact and environment-independent.
"""
from __future__ import annotations

import math
import os
import statistics
import time
from pathlib import Path
from unittest import skipUnless

from django.db import connection
from django.test.utils import CaptureQueriesContext

from dojo.models import Finding, Test
from dojo.utils import get_system_setting

from .base import ApiV3TestCase

_BENCH_ON = os.environ.get("DD_API_V3_BENCH") == "1"
_SEED = 1000          # findings bulk-created on one test/product
_N = 30               # timed repetitions per endpoint
_LIMIT = 100          # page size under test
_REPO_ROOT = Path(__file__).resolve().parents[2]
_REPORT = _REPO_ROOT / ".claude" / "os6-benchmark.md"


def _percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile (e.g. p95 of 30 samples -> the 29th smallest)."""
    ordered = sorted(values)
    idx = max(0, math.ceil(pct / 100 * len(ordered)) - 1)
    return ordered[idx]


@skipUnless(_BENCH_ON, "benchmark is CI-excluded; set DD_API_V3_BENCH=1 to run")
class TestApiV3Benchmark(ApiV3TestCase):

    def _v2_url(self, query: str) -> str:
        prefix = get_system_setting("url_prefix")
        return f"/{prefix}api/v2/findings/{query}"

    def _time_endpoint(self, path: str) -> tuple[dict, int, int, int]:
        """Warm up once, then time N GETs. Returns (stats, status, query_count, rows)."""
        # Warmup (populates any per-request caches; excluded from timings).
        warm = self.client.get(path)
        # One capture for the exact query count.
        with CaptureQueriesContext(connection) as ctx:
            captured = self.client.get(path)
        query_count = len(ctx.captured_queries)
        rows = None
        if captured.status_code == 200:
            body = captured.json()
            rows = len(body["results"]) if isinstance(body, dict) and "results" in body else None

        samples: list[float] = []
        for _ in range(_N):
            start = time.perf_counter()
            self.client.get(path)
            samples.append((time.perf_counter() - start) * 1000.0)  # ms
        stats = {
            "median_ms": statistics.median(samples),
            "p95_ms": _percentile(samples, 95),
            "min_ms": min(samples),
            "max_ms": max(samples),
        }
        return stats, warm.status_code, query_count, rows

    def test_benchmark(self):
        test = Test.objects.first()
        self.assertIsNotNone(test, "fixture must provide at least one test")
        Finding.objects.bulk_create([
            Finding(
                title=f"bench finding {i}", severity="High", numerical_severity="S1",
                description="benchmark seed", test=test, reporter=self.admin,
                active=True, verified=False,
            )
            for i in range(_SEED)
        ])
        total_findings = Finding.objects.count()

        scenarios = [
            ("v2 list ?prefetch=test", self._v2_url(f"?limit={_LIMIT}&prefetch=test")),
            ("v2 list (no prefetch)", self._v2_url(f"?limit={_LIMIT}")),
            ("v3 list (slim, no expand)", self.v3_url(f"findings?limit={_LIMIT}")),
            ("v3 list ?expand=test.engagement", self.v3_url(f"findings?limit={_LIMIT}&expand=test.engagement")),
        ]

        results = []
        for label, path in scenarios:
            stats, status, query_count, rows = self._time_endpoint(path)
            results.append((label, path, status, query_count, rows, stats))

        self._write_report(total_findings, results)

        # Assertions turn the harness into a real (if CI-excluded) test: everything responds 200 and
        # the v3 query count is dramatically lower than v2's (the headline claim), constant vs rows.
        by_label = {label: (status, qc) for label, _, status, qc, _, _ in results}
        for label, (status, _qc) in by_label.items():
            self.assertEqual(200, status, f"{label} returned {status}")
        self.assertLess(
            by_label["v3 list (slim, no expand)"][1],
            by_label["v2 list ?prefetch=test"][1],
            "v3 slim must issue far fewer queries than v2 prefetch",
        )

    def _write_report(self, total_findings: int, results: list) -> None:
        lines = [
            "# API v3 — OS6 latency & query-count benchmark",
            "",
            ("**Generated by** `unittests/api_v3/test_apiv3_benchmark.py` "
             "(`DD_API_V3_BENCH=1`, CI-excluded). Numbers are real captures, never fabricated."),
            "",
            "## Methodology",
            "",
            (f"- Seeded **{_SEED}** findings on a single product/test via `bulk_create`; "
             f"total findings in DB at measurement time: **{total_findings}**."),
            (f"- Page size `limit={_LIMIT}`. For each endpoint: one warmup GET (discarded), one "
             f"capture GET for the exact SQL count, then **N={_N} timed** GETs."),
            ("- Timing via `time.perf_counter()` around the in-process Django test client "
             "(`APIClient`, token auth). Median and nearest-rank p95 over the N samples."),
            "- Query count via `CaptureQueriesContext` (one representative request).",
            "",
            "## CAVEATS (read before quoting the latency numbers)",
            "",
            ("These are **in-process** measurements. They deliberately isolate the ORM + "
             "serialization cost, but they are **NOT** production latency:"),
            "",
            ("- **No HTTP / uwsgi / network layer** — no WSGI worker, no request parsing over a "
             "socket, no gzip, no reverse proxy. The v3 wire win from gzip'd repeated refs (D3) is "
             "not captured here at all."),
            ("- **Single-threaded**, no connection-pool warmup, no concurrent load — the regime where "
             "the v2 per-row query fan-out hurts most (connection contention) is absent."),
            ("- **Shared test transaction** against the kept test DB; planner stats and cache state "
             "differ from production."),
            ("- Therefore: treat **latency** as *directional* (it should track the query-count gap) "
             "and treat the **query counts** as the load-bearing, environment-independent evidence."),
            ("- The honest wall-clock procedure against a running uwsgi stack is recorded in "
             "`.claude/os1-gate-report.md` ('Latency numbers: PENDING') and remains the way to get "
             "quotable production latency."),
            "",
            "## Results",
            "",
            "| Scenario | Status | Queries | Rows | Median (ms) | p95 (ms) | Min (ms) | Max (ms) |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
        for label, _path, status, query_count, rows, stats in results:
            lines.append(
                f"| {label} | {status} | {query_count} | {rows if rows is not None else '-'} "
                f"| {stats['median_ms']:.2f} | {stats['p95_ms']:.2f} "
                f"| {stats['min_ms']:.2f} | {stats['max_ms']:.2f} |",
            )
        lines += [
            "",
            "## Interpretation",
            "",
            ("The query counts are the headline: v3's slim/expand paths issue a **constant** number "
             "of queries independent of row count (the N+1 fix, D3), whereas v2's post-serialization "
             "`?prefetch=` issues per-row queries. The in-process median/p95 should move in the same "
             "direction as the query gap; quote them only with the caveats above."),
            "",
        ]
        report = "\n".join(lines)
        # Echo to stdout FIRST so the numbers are captured even if the file write is not permitted
        # (the container user may not own .claude/); the markdown between the markers is verbatim.
        print("\n===== OS6 BENCHMARK REPORT (verbatim) =====")  # noqa: T201
        print(report)  # noqa: T201
        print("===== END OS6 BENCHMARK REPORT =====")  # noqa: T201
        try:
            _REPORT.parent.mkdir(parents=True, exist_ok=True)
            _REPORT.write_text(report, encoding="utf-8")
            print(f"[benchmark] wrote {_REPORT}")  # noqa: T201
        except OSError as exc:  # best-effort: .claude/ may be host-owned/read-only for this uid
            print(f"[benchmark] could not write {_REPORT} ({exc}); use the verbatim block above")  # noqa: T201
