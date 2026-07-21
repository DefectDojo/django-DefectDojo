r"""
Real request/response capture harness -> ``api_v3_examples.md`` (repo root) (OS6, §6).

**CI-EXCLUDED.** Gated behind ``DD_API_V3_EXAMPLES=1`` so the normal suite never runs it. Run:

    docker compose exec -e DD_API_V3_EXAMPLES=1 uwsgi \\
        python manage.py test unittests.api_v3.test_apiv3_examples -v2 --keepdb

Every example is a **real** request executed through the in-process Django test client against the
fixture data; the response bodies are rendered **verbatim** (only the caller's token is redacted and
long ``results`` lists are truncated to ~3 rows with an explicit marker, per the task). The rendered
markdown is written to ``/app/api_v3_examples.md`` (the repo root is bind-mounted, so it persists to
the host) and echoed to stdout between markers as a fallback. Nothing is hand-written or fabricated.
"""
from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
from unittest import skipUnless
from urllib.parse import urlsplit

from dojo.finding.helper import save_cwes, save_vulnerability_ids
from dojo.location.models import Location, LocationFindingReference
from dojo.models import Finding, Product, Product_Type
from dojo.utils import get_system_setting

from .base import ApiV3TestCase

_EXAMPLES_ON = os.environ.get("DD_API_V3_EXAMPLES") == "1"
_REPO_ROOT = Path(__file__).resolve().parents[2]
_OUT = _REPO_ROOT / "api_v3_examples.md"
_TOKEN_PLACEHOLDER = "<your-api-token>"       # doc placeholder, not a secret
_MAX_ROWS = 3


def _truncate(body: object) -> object:
    """Truncate a list envelope's ``results`` to ~3 rows with an explicit marker (task rule)."""
    if isinstance(body, dict) and isinstance(body.get("results"), list):
        results = body["results"]
        if len(results) > _MAX_ROWS:
            trimmed = dict(body)
            hidden = len(results) - _MAX_ROWS
            trimmed["results"] = [*results[:_MAX_ROWS], f"... {hidden} more result(s) truncated"]
            return trimmed
    return body


def _pretty(body: object) -> str:
    return json.dumps(body, indent=2, default=str)


@skipUnless(_EXAMPLES_ON, "examples harness is CI-excluded; set DD_API_V3_EXAMPLES=1 to run")
class TestApiV3Examples(ApiV3TestCase):

    def setUp(self):
        super().setUp()
        self.blocks: list[str] = []
        self.prefix = get_system_setting("url_prefix")

    def _v2_findings_url(self, query: str = "") -> str:
        return f"/{self.prefix}api/v2/findings/{query}"

    # --- capture / render -----------------------------------------------------------------------
    def _record(
        self, *, title: str, intro: str, method: str, url: str, response,
        req_headers: list[str] | None = None, req_body: str | None = None, truncate: bool = False,
        body_transform=None,
    ) -> None:
        headers = req_headers or [f"Authorization: Token {_TOKEN_PLACEHOLDER}"]
        lines = [f"### {title}", "", intro, "", "**Request**", "", "```http", f"{method} {url}"]
        lines += headers
        if req_body is not None:
            lines += ["", req_body]
        lines += ["```", "", f"**Response** — `{response.status_code}`", ""]
        if getattr(response, "streaming", False):
            lines += ["```", "<binary stream>", "```", ""]
        else:
            try:
                body = response.json()
                if body_transform is not None:
                    body = body_transform(body)
                if truncate:
                    body = _truncate(body)
                rendered = _pretty(body)
            except ValueError:
                rendered = response.content.decode("utf-8", "replace") or "<empty body>"
            lines += ["```json", rendered, "```", ""]
        self.blocks.append("\n".join(lines))

    def _record_csv(self, *, title: str, intro: str, url: str, response, max_lines: int = 4) -> None:
        """Render a streaming CSV export: request, the response headers, and the first ~4 lines."""
        lines = [
            f"### {title}", "", intro, "", "**Request**", "", "```http", f"GET {url}",
            f"Authorization: Token {_TOKEN_PLACEHOLDER}", "```", "",
            f"**Response** — `{response.status_code}`", "", "Response headers:", "", "```http",
        ]
        lines += [
            f"{header}: {response[header]}"
            for header in ("Content-Type", "Content-Disposition", "X-API-Status")
            if response.has_header(header)
        ]
        lines += ["```", "", f"Body (first {max_lines} lines):", "", "```csv"]
        content = b"".join(response.streaming_content).decode("utf-8")
        body_lines = content.splitlines()
        lines += body_lines[:max_lines]
        hidden = len(body_lines) - len(body_lines[:max_lines])
        if hidden > 0:
            lines.append(f"... {hidden} more row(s) truncated")
        lines += ["```", ""]
        self.blocks.append("\n".join(lines))

    # --- cursor helpers -------------------------------------------------------------------------
    @staticmethod
    def _relativize(url: str) -> str:
        """Strip scheme+host from an absolute ``next`` URL so the test client can follow it verbatim."""
        parts = urlsplit(url)
        return parts.path + (f"?{parts.query}" if parts.query else "")

    @staticmethod
    def _shorten_cursor(url: str) -> str:
        """Truncate the opaque ``cursor=`` token in a URL for readability (marked as truncated)."""
        marker = "cursor="
        idx = url.find(marker)
        if idx == -1:
            return url
        start = idx + len(marker)
        end = url.find("&", start)
        if end == -1:
            end = len(url)
        value = url[start:end]
        if len(value) > 24:
            value = value[:20] + "...<cursor truncated>"
        return url[:start] + value + url[end:]

    def _shorten_next_cursor(self, body):
        """``body_transform`` for cursor envelopes: truncate the opaque cursor in ``next``."""
        if isinstance(body, dict) and isinstance(body.get("next"), str):
            body = dict(body)
            body["next"] = self._shorten_cursor(body["next"])
        return body

    # --- the harness ----------------------------------------------------------------------------
    def test_capture_examples(self):
        finding = Finding.objects.select_related("test__engagement__product").first()
        self.assertIsNotNone(finding)

        # Attach a couple of URL location edges so the expand=locations / sub-resource examples show
        # real edge rows (locations are import-driven; seeding here only makes the doc illustrative).
        for value, status in (("https://example.com/login", "Active"), ("https://example.com/admin", "Mitigated")):
            loc = Location.objects.create(location_type="url", location_value=value)
            LocationFindingReference.objects.create(location=loc, finding=finding, status=status)

        # Seed a few High+active findings so the filtered page-2 envelope shows next AND previous.
        Finding.objects.bulk_create([
            Finding(title=f"example high active {i}", severity="High", numerical_severity="S1",
                    description="doc seed", test=finding.test, reporter=self.admin, active=True, verified=True)
            for i in range(6)
        ])

        self._capture_findings(finding)
        self._capture_assets()
        self._write(_OUT)

    # --- findings (the complex entity) ----------------------------------------------------------
    def _capture_findings(self, finding: Finding) -> None:
        fid = finding.id
        # Populate a detail-only field (`impact`) plus the identity-row fields (scalar `cwe`, the
        # `cwes` list incl. an extra CWE, `vulnerability_ids`, and `tags`) so the captured finding
        # bodies show them with real values rather than empties (§4.5 / §12 2026-07-21). These ride on
        # every slim row, so the list/cursor/CSV examples below display them without a detail fetch.
        finding.impact = "Unauthorized disclosure of customer data if exploited."
        finding.cwe = 79
        finding.unsaved_cwes = [89]
        save_cwes(finding)  # persists Finding_CWE rows: primary CWE-79 first, then CWE-89
        save_vulnerability_ids(finding, ["CVE-2024-3094", "GHSA-8r3f-844x-mdgq"])  # sets finding.cve too
        finding.tags = ["internal", "tls"]
        finding.save()

        self._record(
            title="Finding — GET detail (slim + detail fields)",
            intro="Retrieve a single finding. Relations render as closed `{id, name}` refs (§4.4); the "
                  "parent chain (`test`/`engagement`/`asset`/`organization`) is denormalized onto the "
                  "finding. `locations_count` is an annotation; the full list is a sub-resource (§4.14).",
            method="GET", url=self.v3_url(f"findings/{fid}"),
            response=self.client.get(self.v3_url(f"findings/{fid}")),
        )

        self._record(
            title="Finding — GET detail with `?expand=test.engagement,locations`",
            intro="`?expand=` swaps a ref for the target's slim object inline and drives real "
                  "`select_related`/`prefetch_related` (§4.6). `expand=locations` replaces "
                  "`locations_count` with edge rows `{location, status, audit_time, auditor}`.",
            method="GET", url=self.v3_url(f"findings/{fid}?expand=test.engagement,locations"),
            response=self.client.get(self.v3_url(f"findings/{fid}?expand=test.engagement,locations")),
        )

        self._record(
            title="Finding — GET list, filtered (`severity=High&active=true`) + pagination page 2",
            intro="The filter grammar is a documented, snapshot-tested vocabulary (§4.9). The list "
                  "envelope is always `{count, next, previous, results, meta?}` (I1); `next`/`previous` "
                  "are opaque URLs (D4). Here `limit=2&offset=2` is page 2, so both are non-null.",
            method="GET",
            url=self.v3_url("findings?severity=High&active=true&limit=2&offset=2"),
            response=self.client.get(self.v3_url("findings?severity=High&active=true&limit=2&offset=2")),
            truncate=True,
        )

        self._capture_cursor()

        self._record(
            title="Finding — GET list with `?include=counts`",
            intro="`?include=counts` adds severity/status totals computed over the *filtered, "
                  "authorized* queryset into `meta` in one aggregate query — no second round-trip (§4.8).",
            method="GET", url=self.v3_url("findings?include=counts&limit=2"),
            response=self.client.get(self.v3_url("findings?include=counts&limit=2")),
            truncate=True,
        )

        self._record(
            title="Finding — GET list with `?fields=` opting into a detail field (`impact`)",
            intro="A list returns the slim shape by default. `?fields=` may name any **detail** field "
                  "(here `impact`, normally only on the detail endpoint) and it is returned on the list "
                  "with no second request (§4.7). Fields are row-columns, so this is a wider `SELECT` on "
                  "the same single query — never a per-row cost; the default list defers these heavy "
                  "columns entirely and requesting one un-defers exactly it.",
            method="GET",
            url=self.v3_url(f"findings?id__in={fid}&fields=id,title,severity,impact"),
            response=self.client.get(self.v3_url(f"findings?id__in={fid}&fields=id,title,severity,impact")),
            truncate=True,
        )

        self._capture_csv_export()

        # notes sub-resource: POST then GET
        note_body = {"entry": "Reviewed with the security team; scheduled for the next sprint.", "private": False}
        self._record(
            title="Finding — POST a note (sub-resource)",
            intro="Notes are one generic sub-resource across resources (§4.12). Authorization is "
                  "inherited from the parent finding.",
            method="POST", url=self.v3_url(f"findings/{fid}/notes"),
            req_headers=[f"Authorization: Token {_TOKEN_PLACEHOLDER}", "Content-Type: application/json"],
            req_body=_pretty(note_body),
            response=self.client.post(self.v3_url(f"findings/{fid}/notes"), note_body, format="json"),
        )
        self._record(
            title="Finding — GET notes (sub-resource)",
            intro="List a finding's notes (paginated envelope). v2 parity: all notes are returned; "
                  "`private` is a label, not a per-user read filter (§12).",
            method="GET", url=self.v3_url(f"findings/{fid}/notes"),
            response=self.client.get(self.v3_url(f"findings/{fid}/notes")), truncate=True,
        )

        self._record(
            title="Finding — GET locations (sub-resource, edge rows)",
            intro="Finding↔Location is many-to-many with status on the edge (D5). Each row is a "
                  "location ref (carrying `type`) plus the edge `status`/`audit_time`/`auditor` (§4.14).",
            method="GET", url=self.v3_url(f"findings/{fid}/locations"),
            response=self.client.get(self.v3_url(f"findings/{fid}/locations")), truncate=True,
        )

        # PATCH a *separate* finding so the read examples above stay pristine.
        patch_target = Finding.objects.create(
            title="Example finding to patch", severity="Low", numerical_severity="S3",
            description="before patch", test=finding.test, reporter=self.admin, active=True, verified=False,
        )
        patch_body = {"severity": "Medium", "verified": True}
        self._record(
            title="Finding — PATCH (partial update)",
            intro="Partial update (PATCH-only in alpha; §12). Write payloads reference relations by "
                  "integer id and only send changed fields; the response is the updated detail shape.",
            method="PATCH", url=self.v3_url(f"findings/{patch_target.id}"),
            req_headers=[f"Authorization: Token {_TOKEN_PLACEHOLDER}", "Content-Type: application/json"],
            req_body=_pretty(patch_body),
            response=self.client.patch(self.v3_url(f"findings/{patch_target.id}"), patch_body, format="json"),
        )

        self._capture_cwes_write(finding)
        self._capture_put(finding)

        # POST /import (multipart). Described request + real JSON response.
        self._capture_import()

    # --- cursor pagination (D4/§4.3) ------------------------------------------------------------
    def _capture_cursor(self) -> None:
        query = "findings?pagination=cursor&severity=High&active=true&limit=2"
        page1 = self.client.get(self.v3_url(query))
        self._record(
            title="Finding — GET list, cursor pagination (`?pagination=cursor`) — page 1",
            intro="Forward-only keyset mode for export/sync consumers (D4/§4.3). Same envelope, but "
                  "`count` and `previous` are always `null` and `next` carries an opaque, signed "
                  "`cursor=` token (truncated below). No `COUNT` query runs; the page is read as "
                  "`limit+1` rows to detect a next page. Keyset-safe orderings only (`id` default, plus "
                  "`created`/`updated` where a resource declares them); filters/`fields=`/`expand=`/"
                  "`include=` compose unchanged.",
            method="GET", url=self.v3_url(query),
            response=page1, truncate=True, body_transform=self._shorten_next_cursor,
        )
        next_url = page1.json().get("next")
        if next_url:
            follow = self._relativize(next_url)
            self._record(
                title="Finding — GET list, cursor pagination — page 2 (following `next`)",
                intro="Follow the page-1 `next` URL verbatim (opaque). The signed cursor encodes only the "
                      "ordering + last-row key position (never the filters), so the keyset predicate reads "
                      "exactly the rows after that position — no offset, no count. When `next` is `null` "
                      "the walk is complete.",
                method="GET", url=self._shorten_cursor(follow),
                response=self.client.get(follow), truncate=True, body_transform=self._shorten_next_cursor,
            )

    # --- CSV export (D6/§4.15) ------------------------------------------------------------------
    def _capture_csv_export(self) -> None:
        query = ("findings/export.csv?severity=High&o=id"
                 "&fields=id,title,severity,asset,cwe,cwes,vulnerability_ids,tags")
        self._record_csv(
            title="Finding — GET export.csv (CSV export, the second projection of the filter contract)",
            intro="`GET /<resource>/export.csv` (§4.15) streams the **whole** filtered, authorized set as "
                  "CSV using the identical filter/`o=`/`q=`/`fields=` contract as the list — there is no "
                  "pagination (`expand`/`include`/`limit`/`offset`/`pagination`/`cursor` → 400). A `{id, "
                  "name}` ref flattens to `<key>_id`/`<key>_name` columns (a location ref adds "
                  "`<key>_type`); list fields (`tags`, `cwes`, `vulnerability_ids`) join with `;`. Cells "
                  "starting with `= + - @` or TAB are quote-prefixed (spreadsheet formula-injection "
                  "defense). A zero-row export still emits the header row.",
            url=self.v3_url(query), response=self.client.get(self.v3_url(query)),
        )

    # --- cwes on writes (§12, 2026-07-21) -------------------------------------------------------
    def _capture_cwes_write(self, finding: Finding) -> None:
        target = Finding.objects.create(
            title="Example finding for cwes write", severity="Low", numerical_severity="S3",
            description="before cwes patch", test=finding.test, reporter=self.admin,
            active=True, verified=False,
        )
        patch_body = {"cwes": [79, 89, 352]}
        self._record(
            title="Finding — PATCH `cwes` (write a CWE list; scalar `cwe` mirrors the primary)",
            intro="Finding writes accept a flat `cwes: list[int]` (§12, 2026-07-21) — symmetric with the "
                  "read shape and parallel to `vulnerability_ids`. The first entry is mirrored into the "
                  "scalar `cwe`; the `Finding_CWE` rows persist primary-first. An omitted `cwes` leaves "
                  "existing rows untouched; an explicit `[]` clears the extras.",
            method="PATCH", url=self.v3_url(f"findings/{target.id}"),
            req_headers=[f"Authorization: Token {_TOKEN_PLACEHOLDER}", "Content-Type: application/json"],
            req_body=_pretty(patch_body),
            response=self.client.patch(self.v3_url(f"findings/{target.id}"), patch_body, format="json"),
        )
        self._record(
            title="Finding — GET detail after the `cwes` PATCH (read-back)",
            intro="Read-back confirms persistence: `cwes` returns the list in storage order and the "
                  "scalar `cwe` mirror is the primary (first) entry.",
            method="GET", url=self.v3_url(f"findings/{target.id}"),
            response=self.client.get(self.v3_url(f"findings/{target.id}")),
        )

    # --- PUT full replace (§4.11) ---------------------------------------------------------------
    def _capture_put(self, finding: Finding) -> None:
        target = Finding.objects.create(
            title="Example finding to replace", severity="High", numerical_severity="S1",
            description="original description", test=finding.test, reporter=self.admin,
            active=True, verified=True,
            mitigation="Upgrade the affected dependency to a patched release.",
            impact="Remote code execution on the affected host.",
        )
        put_body = {
            "title": "Example finding replaced via PUT",
            "severity": "Medium",
            "description": "replaced description",
            "active": True,
            "verified": False,
        }
        self._record(
            title="Finding — PUT (full replace)",
            intro="`PUT` is a **full replace** (§4.11): it validates against the create-shaped schema "
                  "(required fields enforced, unknown fields → 400) and applies the body **without** "
                  "`exclude_unset`, so every omitted optional resets to its default — mirroring v2's "
                  "`update(partial=False)`. The finding had `mitigation`/`impact` set, but the PUT body "
                  "omits them, so they reset to `null`. The immutable parent `test` is not in the replace "
                  "schema and is never reassigned (like PATCH). Finding PUT still flows through the "
                  "service (JIRA / risk-acceptance / vuln-id side-effects), never route logic (I6).",
            method="PUT", url=self.v3_url(f"findings/{target.id}"),
            req_headers=[f"Authorization: Token {_TOKEN_PLACEHOLDER}", "Content-Type: application/json"],
            req_body=_pretty(put_body),
            response=self.client.put(self.v3_url(f"findings/{target.id}"), put_body, format="json"),
        )

    def _capture_import(self) -> None:
        from unittests.dojo_test_case import get_unit_tests_scans_path  # noqa: PLC0415

        scan_path = get_unit_tests_scans_path("zap") / "0_zap_sample.xml"
        # Current form (§4.13). Auto-create fields speak the v3 wire names `asset_name` /
        # `organization_name` (D11); there is NO `background`/job field — v3 imports are synchronous.
        import_desc = (
            "multipart/form-data fields (v3 imports are synchronous — there is no `background`/job field):\n"
            "  mode=import                          # auto | import | reimport (default auto)\n"
            "  scan_type=ZAP Scan\n"
            "  engagement=4                         # import target; or test= (reimport); or\n"
            "                                       #   asset_name + engagement_name (+ organization_name)\n"
            "                                       #   + auto_create_context=true  to auto-create the target\n"
            "  file=@0_zap_sample.xml\n"
            "  active=true\n"
            "  verified=true\n"
            "  push_to_jira=false                   # OR-ed with the JIRA project's push_all_issues\n"
            "  close_old_findings=false             # destructive flags are never implied by mode\n"
            "  close_old_findings_product_scope=false"
        )
        with scan_path.open(encoding="utf-8") as scan:
            payload = {"scan_type": "ZAP Scan", "mode": "import", "engagement": 4,
                       "file": scan, "active": "true", "verified": "true"}
            response = self.client.post(self.v3_url("import"), payload, format="multipart")
        self._record(
            title="Import — POST /import (consolidated import/reimport/auto)",
            intro="One endpoint for import, reimport and auto-resolve (§4.13). Destructive flags "
                  "(`close_old_findings`, `close_old_findings_product_scope`) are never implied by mode; "
                  "the response echoes the resolved mode + effective flags. Auto-create fields use the "
                  "v3 wire names `asset_name`/`organization_name` (D11); imports are synchronous (no job "
                  "resource).",
            method="POST", url=self.v3_url("import"),
            req_headers=[f"Authorization: Token {_TOKEN_PLACEHOLDER}",
                         "Content-Type: multipart/form-data"],
            req_body=import_desc, response=response,
        )

    # --- assets (the simple contrast) -----------------------------------------------------------
    def _capture_assets(self) -> None:
        product = Product.objects.first()
        self._record(
            title="Asset — GET detail",
            intro="A simple entity for contrast with findings: identity, `organization` ref, and the "
                  "documented heavier detail fields.",
            method="GET", url=self.v3_url(f"assets/{product.id}"),
            response=self.client.get(self.v3_url(f"assets/{product.id}")),
        )
        self._record(
            title="Asset — GET list",
            intro="Same envelope and grammar as findings; slim rows only on list (§4.5).",
            method="GET", url=self.v3_url("assets?limit=2"),
            response=self.client.get(self.v3_url("assets?limit=2")), truncate=True,
        )

        pt = Product_Type.objects.first()
        create_body = {"name": "Example v3 Asset", "description": "Created via the v3 API examples harness",
                       "organization": pt.id, "lifecycle": "production", "tags": ["pci", "example"]}
        create_resp = self.client.post(self.v3_url("assets"), create_body, format="json")
        self._record(
            title="Asset — POST (create)",
            intro="Create an asset. Relations are referenced by integer id (§4.11); unknown fields "
                  "are rejected (400). Response is the created detail shape (`201`).",
            method="POST", url=self.v3_url("assets"),
            req_headers=[f"Authorization: Token {_TOKEN_PLACEHOLDER}", "Content-Type: application/json"],
            req_body=_pretty(create_body), response=create_resp,
        )

        new_id = create_resp.json().get("id") if create_resp.status_code == 201 else product.id
        patch_body = {"description": "Updated description via PATCH"}
        self._record(
            title="Asset — PATCH (partial update)",
            intro="Partial update; only the changed field is sent.",
            method="PATCH", url=self.v3_url(f"assets/{new_id}"),
            req_headers=[f"Authorization: Token {_TOKEN_PLACEHOLDER}", "Content-Type: application/json"],
            req_body=_pretty(patch_body),
            response=self.client.patch(self.v3_url(f"assets/{new_id}"), patch_body, format="json"),
        )

    # --- output ---------------------------------------------------------------------------------
    def _header(self) -> str:
        prefix = f"/{self.prefix}" if self.prefix else "/"
        base = f"{prefix.rstrip('/')}/api/v3-alpha"
        return "\n".join([
            "# DefectDojo API v3 (alpha) — worked examples",
            "",
            ("> **Auto-generated, do not hand-edit.** Every request/response below was captured by "
             "`unittests/api_v3/test_apiv3_examples.py` (`DD_API_V3_EXAMPLES=1`, CI-excluded) making "
             "**real** in-process requests against the test fixture. Tokens are redacted; long lists "
             "are truncated to ~3 rows. Regenerate with the command in that file's docstring."),
            "",
            f"Captured: {datetime.datetime.now(tz=datetime.UTC).isoformat()}",
            "",
            "## Conventions (see `API_V3_PLAN.md` §4)",
            "",
            (f"- **Mount:** alpha lives at `{base}/` (moves to `/api/v3/` at beta — one migration, D1). "
             "Every response carries `X-API-Status: alpha`."),
            ("- **Auth (D8):** send an existing v2 token as `Authorization: Token <key>` (works "
             "unchanged on v3), or a Django session cookie + `X-CSRFToken` on unsafe methods."),
            ("- **Envelope & pagination (§4.3):** every list is `{count, next, previous, results, meta?}` "
             "and nothing else (I1). `next`/`previous` are opaque URLs. Offset mode is the default "
             "(`limit=25`, max `250`); `?pagination=cursor` opts into forward-only keyset paging "
             "(`count`/`previous` null, opaque signed cursor in `next`)."),
            ("- **Refs (§4.4):** relations render as `{id, name}` (locations add `type`). Write payloads "
             "reference relations by integer id — the asymmetry is intentional (§4.11)."),
            ("- **Writes (§4.11):** `PATCH` is a partial update (only supplied fields change); `PUT` is a "
             "full replace (omitted optionals reset to their defaults). Both reject unknown fields (400)."),
            ("- **CSV export (§4.15):** `GET /<resource>/export.csv` streams the whole filtered, "
             "authorized set as CSV using the identical filter/`o=`/`q=`/`fields=` contract (no "
             "pagination); refs flatten to `_id`/`_name` columns, list fields join with `;`."),
            ("- **`?expand=` (§4.6):** dotted paths swap refs for slim objects inline and drive the "
             "queryset (the real N+1 fix). Budget-guarded."),
            ("- **`?fields=` (§4.7):** comma-separated allowlist; `id` is always included. On a list it "
             "may also request any detail field (a wider SELECT on one query, never per-row)."),
            ("- **`?include=counts` (§4.8):** adds aggregate totals to `meta` over the filtered, "
             "authorized queryset."),
            ("- **Errors (§4.10):** RFC 9457 `application/problem+json` with a `fields` extension for "
             "validation errors."),
            "",
            "---",
            "",
        ])

    def _write(self, out: Path) -> None:
        document = self._header() + "\n\n---\n\n".join(self.blocks) + "\n"
        print("\n===== OS6 API V3 EXAMPLES (verbatim) =====")  # noqa: T201
        print(document)  # noqa: T201
        print("===== END OS6 API V3 EXAMPLES =====")  # noqa: T201
        try:
            out.write_text(document, encoding="utf-8")
            print(f"[examples] wrote {out}")  # noqa: T201
        except OSError as exc:
            print(f"[examples] could not write {out} ({exc}); use the verbatim block above")  # noqa: T201
