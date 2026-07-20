# API v3 Alpha — Combined Implementation Debrief

**Date:** 2026-07-19 · **Branch:** `upstream/feature/api-v3-alpha` · **Status:** all OS phases complete, feature-complete per plan §2
**Final state:** 267 tests green + 2 CI-excluded harnesses · ruff clean · v2 untouched and green · framework: django-ninja 1.6.2 (pydantic 2.13.4 transitive)

How this was built: one Opus subagent per phase working from `API_V3_PLAN.md`; a coordinator reviewed every diff against the §4 contract and §5 invariants and independently re-ran the full suite before each commit. Per-phase detail reports live in `.claude/os*-report.md` (uncommitted).

---

## Commit timeline

| Commit | Phase | Tests after |
|---|---|---:|
| `0102153` | Plan document | — |
| `9ae4abc` | OS1 — kernel + findings read + import | 37 |
| `62c2713` | OS2 — kernel hardening | 65 |
| `31de8e8` | OS3a — product_type/product/user CRUD | 129 |
| `9e27c68` | OS3b — engagement/test CRUD + finding services | 197 |
| `5d9aa8a` | Query sweep harness (N+1 detector) | 198 |
| `65fd508` | OS4 — locations | 229 |
| `36d3c8b` | OS5 — notes/tags/files sub-resources | 252 |
| `9c341420` | OS6 — verification/docs/examples/benchmark | 267 (+2 skipped) |

---

## OS1 — Foundation, findings read path, import, framework gate

**Delivered:** `dojo/api_v3/` kernel (`api.py` mount, `auth.py` TokenAuth reusing the v2 token store + session/CSRF via `django_auth`, `pagination.py` envelope with hybrid exact→planner-estimate counts, `errors.py` RFC 9457 problem+json + DRF boundary adapter, `expand.py` cycle guard + budget + expand-driven `select_related`/`prefetch_related`, `filtering.py` django-filter adapter, `include.py` counts); `dojo/finding/api_v3/` (FindingSlim/Detail, `build_findings_router()`); `dojo/importers/services.py` (`ImportResult` replacing the 7-tuple); `POST /import` with mode auto|import|reimport; conditional mount at `/api/v3-alpha/` gated on `V3_FEATURE_LOCATIONS`.

**Gate (all 7 criteria pass → GO on Ninja):** constant query counts (5 slim / 7 expanded at 10 and 100 rows vs v2 91→271 / 222→762); import DB-state equivalence vs v2; RBAC via `get_authorized_findings`; django-filter reuse proven; both auth modes on the same endpoints; OpenAPI renders; subclass-and-remount seam demo (I4/I5).

**Coordinator review caught:** `locations_count` used `Count("locations")` without `distinct=True` — inflated counts when combined with the `tags__in` join. Fixed pre-commit.

**Notable §12 decisions:** CSRF enforced by `SessionAuth` (ninja 1.6 dropped `NinjaAPI(csrf=)`); no trailing slashes (architect confirmed); `LOGIN_EXEMPT_URLS` append so anonymous gets 401 problem+json, not a login redirect.

## OS2 — Kernel hardening

**Delivered:** severity ordering by rank (query-time Case/When mirroring v2's `numerical_severity`, never alphabetical); strict unknown-filter-param → 400 (typo'd filters must not silently return everything); `FilterSpec` registry + vocabulary snapshot test (contract drift fails CI); `expand=locations` swapping `locations_count` for edge rows via a special renderer with declared prefetch paths; dedicated `fields` problem type; 13-test problem+json error-path sweep; OpenAPI schema-generation guard.

**Architect calls:** `api.py` stays in the kernel package as composition root; strict-400 stance kept; fields/expand interplay deferred to OS4.

## OS3a — product_type, product, user CRUD

**Delivered:** three resources with Slim/Detail/Write/Update schemas (`extra="forbid"` → unknown write field 400), router factories, GET/POST/PATCH/DELETE (no PUT in alpha — additive later), FilterSpecs, canonical slim schemas relocated out of the finding module (is-identity asserted). Deletion mirrors v2 exactly: product/product_type use `async_delete()` or synchronous delete inside `Endpoint.allow_endpoint_init()`; user delete is plain + self-delete guard. `UserSerializer.validate()` rules ported (superuser/staff gating, password write-only, no self-delete).

**Coordinator review caught (the big one):** the agent had opened collaborator-scoped user reads — including emails — to every authenticated user, a PII-exposure widening vs v2's `view_user` config-permission gate, with the absurd side effect of 404 on your own user record. Sent back and corrected: v2-parity `view_user` gate, and plain users see exactly themselves (guaranteed self-read).

## OS3b — engagement/test CRUD + finding writes (the D7 flagship)

**Delivered:** engagement + test resources (same pattern; deletion mirrors v2 — notably *without* the `allow_endpoint_init` wrapper, unlike products, faithfully mirroring v2); `dojo/finding/services.py` with `create_finding`/`update_finding`/`delete_finding` extracted by reconciling **both** reference implementations (v2 serializer + UI `edit_finding` flows); `POST/PATCH/DELETE /findings` as thin routes with the 404-then-403 permission ladder.

**Divergence table (17 rows, in `.claude/os3b-report.md`):** serializer semantics canonical for the API — risk-acceptance processing before field updates, synchronous JIRA push with `force_sync=True` raising on failure (mapped to problem+json 400, tested with mocks), `finding_added` notification on create. Deferred as UI-only to CONV2: `last_reviewed` stamping, false-positive-history reactivation, finding-group handling, burp req/resp, github, jira link/unlink. One deliberate deviation: v3 resyncs `Finding_CWE` when scalar `cwe` changes (v2's scalar path doesn't) — consistency chosen, logged.

Also fixed en route: a pydantic forward-ref shadowing bug (`date` field default shadowing the `date` type).

## Query sweep harness (coordinator-built, architect-requested)

`unittests/api_v3/query_report.py` + `test_apiv3_query_report.py`: captures per-request SQL, normalizes literals, flags the N+1 signature (same shape ≥4× in one request) across **every** mounted v3 GET route with fanned-out rows (15+) so per-row queries can't hide. An OpenAPI completeness gate fails the test whenever a new GET endpoint lacks a representative request — OS4/OS5 were forced to extend it, by construction. Writes `/tmp/apiv3_query_report.md` every run. Result across the finished surface: **zero N+1 flags**.

## OS4 — Locations

**Delivered:** `GET /locations` + `/locations/{id}` read-only (superuser gate — verified faithful mirror of v2 `LocationViewSet`'s `IsSuperUser`; rows still drawn via `get_authorized_locations` as the future RBAC seam); `GET /findings/{id}/locations` (edge rows: location ref + status + audit_time + auditor) and `GET /products/{id}/locations` (location ref + status — the model has no audit columns on the product edge); auditor added to `expand=locations` (closing the OS2 deferral); fields/expand interplay resolved kernel-side (`?fields=` allowlist = schema fields ∪ expandable keys); **flag-off test**: in-process URLconf reload proves `V3_FEATURE_LOCATIONS=False` unmounts all of `/api/v3-alpha/`.

## OS5 — Notes / tags / files sub-resources

**Delivered:** three generic kernel factories (`dojo/api_v3/subresources.py`), attached only where models have real storage — the plan's "all seven resources" was wrong:

| resource | notes | tags | files |
|---|:---:|:---:|:---:|
| finding / engagement / test | ✓ | ✓ | ✓ |
| product | — | ✓ | — |
| product_type / user / location | — | — | — |

**v2 parity findings:** note privacy is report-exclusion only, never a per-user read filter (verified against v2 code paths); tags go through the tagulous `force_lowercase` + inheritance write path; files validate via `FileUpload.clean()` with streamed downloads. Authorization: parent via authorized queryset (404), then per-method permission (403), values mirroring v2's related-object permission classes.

**Known alpha parity gap (recorded, deliberate):** v3 note creation does not yet fire the v2 finding-note side-effects (JIRA comment, `last_reviewed`, @mentions) — those are resource-specific side-effects that belong in services (D7), landing with the convergence track.

## OS6 — Verification, docs, examples, benchmark

**Delivered:**
- **RBAC expand sweep** (15 tests): no expanded object, included count, denormalized parent ref, or sub-resource row ever drawn from outside the caller's authorized querysets — the v3 port of `test_apiv2_prefetch_rbac`'s intent.
- **Benchmark** (1021 findings, limit=100, N=30, in-process — latency directional, query counts load-bearing):

| Scenario | Queries | Median | p95 |
|---|---:|---:|---:|
| v2 `?prefetch=test` | 636 | 521.2 ms | 720.5 ms |
| v2 (no prefetch) | 229 | 192.7 ms | 424.3 ms |
| **v3 slim** | **5** | **37.9 ms** | 45.2 ms |
| **v3 `?expand=test.engagement`** | **7** | **60.2 ms** | 231.1 ms |

- **`api_v3_examples.md`** (repo root, committed): auto-generated verbatim request/response pairs — findings (detail, expand, filtered+paginated lists, `include=counts`, notes, locations edges, import, PATCH) and products as the simple contrast. Regenerate: `DD_API_V3_EXAMPLES=1` harness (CI-excluded).
- **Docs page**: `docs/content/automation/api/api-v3-alpha-docs.md` (next to the v2 page; plain markdown, no unverified shortcodes) — overview, auth (v2 tokens work unchanged), contract summary, v2→v3 mapping, **Known alpha gaps** section, beta URL-migration notice.
- **Invariants I1–I10: all pass** (verdict table in `.claude/os6-report.md`); v2 regression sample untouched-and-green (`test_rest_framework` 879 OK, `test_apiv2_prefetch_rbac` 10 OK); `manage.py check` clean.
- **Scalar docs-UI: deferred** — alpha keeps ninja's built-in Swagger at `/api/v3-alpha/docs`; vendoring a JS bundle into a security product's repo needs its own supply-chain review (swap = one template view + locally vendored asset, sidecar-style).

---

## Post-debrief update (same day, architect review of the gaps)

The architect reviewed the five "gaps" and directed changes; all landed on the branch:

1. **Note side-effects — CLOSED in alpha** (`5686fac`). The notes factory gained an
   `on_note_created` callback; `process_note_added` services fire the verified v2 side-effects
   per resource (finding: JIRA comment + `last_reviewed` + @mentions; engagement/test:
   @mentions only). 8 new tests.
2. **Divergence analysis + fix proposal — delivered** as committed `API_V3_DIVERGENCE_ANALYSIS.md`
   (`e8a49ec`): 19 divergences verified in code, proposed canonical behavior per row for v3 AND v2
   AND the UI, v2-consumer impact assessment (1 potentially breaking / 4 behavioral / 12 invisible),
   sequencing across alpha/CONV1/CONV2. Its one confirmed **v3 regression (D17: delete-time JIRA
   sync silently skipped)** was fixed in the same commit as the notes work, with a pinning test.
3. **Locations URL-only** — reclassified in the docs page as a *platform limitation*, not a v3 gap.
4. **Bulk/workflow actions** — recorded as an explicit architect-confirmed **post-alpha OS backlog**
   (checkbox TODOs) in plan §6.
5. **Approximate counts** — reclassified in the docs page as a *design decision to be aware of*.

## Open items for the architect

1. **Draft PR to `dev`**.
2. **Scalar swap** — pending supply-chain review; not blocking.
3. **Convergence track** — CONV1 (v2 serializers → services), CONV2 (UI views → services; the OS3b divergence table + OS5 side-effect gap are the worklist), CONV3 (delete dead duplicates).
4. Minor deferred additions logged in §12: PUT (full replace), delete-time `push_to_jira` param, `configuration_permissions` on user writes, a v3 self-profile endpoint, filter vocabularies for the edge sub-resources.
5. **TODO (architect-confirmed): port the v2 endpoint-level test corpora to v3** — priority: the import/reimport scenario corpus (`test_import_reimport.py` mixin, `test_apiv2_scan_import_options.py`, `test_importers_closeold.py`) via a **dual-endpoint adapter** (parametrize the existing mixins with a client shim mapping v2 field names to v3's `asset_name`/`organization_name`/`mode=` form) rather than copying — a copy would fork the corpus and drift; then the JIRA push flows; then a scoped pass over the rest of `test_apiv2_*` (much covers surfaces v3 deliberately lacks in alpha). Recorded in plan §6 post-alpha backlog.
5. Operational notes: the two env-gated harnesses run via `docker compose exec -e ...` (`run-unittest.sh` has no env passthrough); `.claude/` was made world-writable so the containerized harness could write reports there.
