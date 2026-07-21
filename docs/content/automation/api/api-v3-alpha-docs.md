---
title: "DefectDojo API v3 (alpha)"
description: "A new, parallel API mounted alongside v2 with refs/expand/fields, one list envelope, and a documented filter contract. Alpha — the contract may change."
draft: false
weight: 3
aliases:
  - /en/api/api-v3-alpha-docs
---

> **Alpha — do not build production dependencies on this.**
> API v3 is in **alpha**. It is mounted at **`/api/v3-alpha/`** precisely so the instability is
> impossible to miss: the alpha contract may change at any time. At **beta the API moves to
> `/api/v3/` and stays there** through GA — so you migrate the URL exactly once, at the moment you
> re-verify against the settled contract. Every v3 response also carries the header
> `X-API-Status: alpha`.

## Overview

API v3 is a **new, parallel API** that runs next to the existing [API v2](../api-v2-docs/). v2 is
**not changed** by v3 and remains fully supported — v3 is entirely additive.

The alpha covers seven objects — `organization`, `asset`, `engagement`, `test`, `finding`,
`location`, `user` — plus a single consolidated `import` endpoint. Everything else stays on v2 until
v3 reaches parity. (`organization` and `asset` are the v3 wire names for what v2 calls `product_type`
and `product` — see [Naming: organizations and assets](#naming-organizations-and-assets).)

What v3 gives you over v2:

- **A slim default response with `{id, name}` refs**, opt-in `?expand=` to inline related objects,
  and `?fields=` to pick columns — instead of v2's post-serialization `?prefetch=`. Because expand
  drives real `select_related`/`prefetch_related`, the query count is **constant regardless of how
  many rows you fetch** (v2's `?prefetch=` issues per-row queries).
- **One list envelope** for every collection, with optional aggregate totals in `meta`.
- **One documented, versioned filter contract** shared across every list.
- **RFC 9457 `application/problem+json`** errors with a `fields` extension for validation.

### Interactive docs

- Interactive API reference (Swagger UI): **`/api/v3-alpha/docs`**
- Modern API reference (Scalar): **`/api/v3-alpha/reference`**
- OpenAPI schema: **`/api/v3-alpha/openapi.json`** (`info.version = 3.0.0-alpha`)

The "try it out" flow works with your logged-in session, or paste a token (see below).

The Scalar page loads its UI from the jsDelivr CDN with a **version-pinned URL and a Subresource
Integrity hash** — the browser refuses to run the bundle if the CDN ever serves different bytes,
and nothing is vendored into DefectDojo. Consequence: on air-gapped deployments the Scalar page
cannot load; Swagger UI at `/docs` serves its assets locally and always works.

## Authentication

Two modes are active on **every** endpoint:

- **Token — your existing v2 token works unchanged.** Send `Authorization: Token <key>`. v3
  validates against the same token store as v2, so a key that works on `/api/v2/` works on
  `/api/v3-alpha/` the same day — no new token, no re-issue.

  ```
  Authorization: Token c8572a5adf107a693aa6c72584da31f4d1f1dcff
  ```

- **Django session + CSRF.** A session cookie plus an `X-CSRFToken` header on unsafe methods
  (`POST`/`PATCH`/`PUT`/`DELETE`). This is what the first-party web UI uses.

Anonymous requests get `401` `application/problem+json`. Authentication is separate from
authorization: after a request authenticates, object access flows through exactly the same
`get_authorized_*` querysets and RBAC as v2.

## The contract in one page

### List envelope

Every list returns the same closed envelope — and nothing else:

```jsonc
{
  "count": 4321,          // exact below a cap; a planner estimate above it (see Known gaps)
  "next": "https://.../api/v3-alpha/findings?limit=25&offset=50&severity=High",
  "previous": null,
  "results": [ /* slim objects */ ],
  "meta": { }             // present only when ?include= adds content
}
```

`limit` defaults to `25`, max `250`; `offset` ≥ 0. **Treat `next`/`previous` as opaque URLs** — do
not construct them yourself.

### Cursor (keyset) pagination

For export/sync consumers, opt into forward-only keyset pagination with `?pagination=cursor` on any
top-level list endpoint (findings, assets, organizations, engagements, tests, users, locations). The
envelope is unchanged, with two differences:

- `count` is always `null` (cursor mode never counts — that is the point: no `COUNT` query, so cost
  is constant per page regardless of collection size).
- `previous` is always `null` — cursor mode is **forward-only** (GitLab-style). Walk a collection by
  following `next` until it is `null`; there is no backward cursor.

`next` is the same URL carrying an opaque, signed `cursor=` token. **Treat it as opaque** — do not
decode or construct it. Cursors are tamper-proof; a modified, corrupt, or ordering-mismatched cursor
returns `400 application/problem+json` (pagination error type).

Sorting is restricted to **keyset-safe orderings** — `id`, `created`, `updated` (each with an
optional `-` prefix for descending), whichever a resource declares. Every ordering has a
deterministic `id` tiebreaker appended automatically. The default (no `o=`) is `id` ascending. A
resource without `created`/`updated` columns permits `id` only. Any other `o=` value (or more than
one field) returns `400`:

| Resource | Keyset-safe orderings (each ± direction) |
|---|---|
| findings, assets, organizations, engagements, tests | `id`, `created`, `updated` |
| users, locations | `id` |

```jsonc
// GET /api/v3-alpha/findings?pagination=cursor&limit=25&o=-updated&severity=High
{
  "count": null,
  "next": "https://.../api/v3-alpha/findings?limit=25&o=-updated&severity=High&pagination=cursor&cursor=eyJ...",
  "previous": null,
  "results": [ /* slim objects */ ]
}
```

Filters, `q=`, `fields=`, `expand=`, and `include=counts` all compose with cursor mode exactly as
with offset mode (`include=counts` still fills `meta.counts` even though `count` is `null`).
**Caveat:** the cursor encodes only the ordering and position, **not** your filters — changing a
filter (or the ordering) partway through a walk invalidates the position and yields undefined
results for the rest of the walk. Start a fresh walk if you change any filter.

### Refs

Every relation renders by default as a closed ref:

```jsonc
{ "id": 42, "name": "Q3 Pentest" }
```

The relation key tells you the type, so refs carry no `type` field — **except** location refs, which
add `"type": "<location_type>"`. On writes you reference a relation by its **integer id**
(`"test": 9`); on reads you get a ref back. This asymmetry is intentional.

Two update verbs are offered on every writable resource (findings, assets, organizations,
engagements, tests, users; locations stay read-only). **`PATCH`** is a partial update — only the
fields you send change. **`PUT`** is a full replace: it validates against the same required fields
as create and resets any omitted optional field back to its default, mirroring v2's
`update(partial=False)`. Both reject unknown fields (`400`) and share the same permission ladder. An
immutable parent (a finding's `test`, a test's `engagement`) is never reassignable on either verb.

### `?expand=`, `?fields=`, `?include=`

| Param | Does | Example |
|---|---|---|
| `?expand=` | Swaps a ref for the target's slim object **inline** and drives the queryset. Comma-separated dotted paths, budget-guarded. | `?expand=test.engagement,reporter` |
| `?fields=` | Allowlist of fields to return (`id` always included). The picker facility; on a list it may also request any **detail** field. | `?fields=id,title,impact` |
| `?include=counts` | Adds severity/status totals over the **filtered, authorized** queryset to `meta`, in one query — no second round-trip. | `?include=counts` |

**`?fields=` on lists may opt up into the detail shape.** A list returns the slim shape by default.
`?fields=` accepts any field in the slim **or** the detail set (plus expand keys), so a list can pull
a normally detail-only field like `impact` or `references` without a second request to the detail
endpoint — `GET /findings?fields=id,title,impact`. Fields are plain row-columns, so this is a wider
`SELECT` on the same single query, never a per-row cost: the default list stops fetching the heavy
detail columns from the DB entirely, and naming one in `?fields=` un-defers exactly that column.
**Guard:** only *row-columns* are eligible. Anything computed per row (SLA/age math, per-row counts)
is permanently out of `?fields=` — it would reintroduce the N+1 the slim default removes. An unknown
field name still returns `400`.

A finding's locations are special: `?expand=locations` replaces the cheap `locations_count` with the
full edge rows `{location, status, audit_time, auditor}`.

### Filter grammar

The grammar is fixed and the per-object vocabulary is documented and snapshot-tested:

- exact `field=`, and lookups `field__gte` / `__lte` / `__gt` / `__lt` / `__in` / `__icontains` /
  `__isnull` (`__in` takes comma-separated values),
- multi-sort `o=` (comma list, `-` prefix for descending, e.g. `o=-severity,date`),
- free-text `q=`.

Unknown filter params, unknown `?fields=`, and unknown/over-budget `?expand=` all return `400`
`application/problem+json`.

### Errors

```jsonc
{ "type": "https://docs.defectdojo.com/api/v3/errors/validation",
  "title": "Validation failed", "status": 400,
  "detail": "2 fields failed validation",
  "fields": { "severity": ["Not a valid choice."], "date": ["Required."] } }
```

`401` unauthenticated · `403` forbidden · `404` unknown **or unauthorized** object (existence is
never leaked) · `400` validation/expand/filter errors.

## v2 → v3 mapping

This table doubles as the rename documentation (D11): `product_type` → `organization`,
`product` → `asset` on the v3 wire.

| Object | v2 | v3 (alpha) | Notes |
|---|---|---|---|
| Organization (v2 "product type") | `/api/v2/product_types/` | `/api/v3-alpha/organizations` | **Renamed** (D11); CRUD (`PATCH` partial + `PUT` full replace) |
| Asset (v2 "product") | `/api/v2/products/` | `/api/v3-alpha/assets` | **Renamed** (D11); CRUD |
| Engagement | `/api/v2/engagements/` | `/api/v3-alpha/engagements` | CRUD |
| Test | `/api/v2/tests/` | `/api/v3-alpha/tests` | CRUD |
| Finding | `/api/v2/findings/` | `/api/v3-alpha/findings` | CRUD + `?expand=`, `?include=counts` |
| Location | `/api/v2/endpoints/` (legacy `Endpoint`) | `/api/v3-alpha/locations` | **Concept change** (see below); read-only in alpha |
| User | `/api/v2/users/` | `/api/v3-alpha/users` | Read + self; admin-only writes |
| Import | `/api/v2/import-scan/` + `/api/v2/reimport-scan/` | `/api/v3-alpha/import` | **Consolidated** — one endpoint, `mode=auto\|import\|reimport` |

### Naming: organizations and assets

v3 speaks the product's new domain language: what v2 calls a **product type** is an
**`organization`** on the v3 wire, and what v2 calls a **product** is an **`asset`**. This renames
the wire surface consistently and completely (D11, "all-or-nothing"): the paths (`/organizations`,
`/assets`), the ref keys (`finding.asset`, `finding.organization`, `engagement.asset`,
`asset.organization`), the filter params (`asset=`, `organization=`, …), the `?expand=` keys
(`expand=asset`, `expand=organization`), the import form fields (`asset_name`, `organization_name`),
the OpenAPI tags and schema classes, and this documentation.

**Why now:** a brand-new API should not bake the legacy names into a surface that clients will
codegen against for years. The alpha is the only time this rename is free — after beta it would mean
permanent aliases and deprecations.

**Unconditional — the API naming does not follow the UI relabel flag.** The web UI's
product-type→organization / product→asset relabel is governed by
`DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL` (default on). The **v3 API ignores that flag**: v3 always
speaks `organizations`/`assets` regardless of the deployment's UI labels. A per-instance API contract
would be poison for code generation, so the wire names are fixed.

**Not renamed:** the underlying Django models (`Product_Type`, `Product`), the database tables, and
the internal module paths are unchanged — the DTO layer is exactly what decouples the wire names from
the models. (A handful of scalar model-column fields keep their names on the wire — the
`organization` flags `critical_product`/`key_product` and the `asset` user-role ref `asset_manager`,
whose model column is `product_manager`; these are model-field passthroughs, not entity references.)

### Locations replace endpoints

v3 does not expose the legacy `Endpoint` model. A finding relates to **locations** many-to-many, with
the status (`Active` / `Mitigated` / `FalsePositive` / `RiskAccepted` / `OutOfScope`) carried on the
edge. Slim findings carry `locations_count`; the full edge list is a sub-resource:

- `GET /api/v3-alpha/findings/{id}/locations` → `{ location: {id, name, type}, status, audit_time, auditor }`
- `GET /api/v3-alpha/assets/{id}/locations` → `{ location: {id, name, type}, status }`

### Import in one call

`POST /api/v3-alpha/import` (multipart) covers all three flows. `mode=auto` resolves an existing
target via `asset_name` + `engagement_name` (+ optional `organization_name`); `import` and `reimport`
are explicit. **Destructive flags are never implied by mode** — if you omit `close_old_findings`, the
importer default applies and the response echoes the effective value:

```jsonc
{ "mode_resolved": "reimport", "test": { "id": 9, "name": "ZAP Scan" },
  "statistics": { "new": 4, "reactivated": 1, "closed": 2, "untouched": 37 },
  "close_old_findings": true }
```

## One way to do notes, tags and files

Where v2 accreted per-resource actions and mechanisms, v3 has **one generic sub-resource** for each,
attached to every resource whose model stores it (notes/files: finding, engagement, test; tags:
those plus asset):

```
GET / POST         /api/v3-alpha/<resource>/{id}/notes      { "entry": "...", "private": false }
GET / PUT / POST   /api/v3-alpha/<resource>/{id}/tags       { "tags": ["pci"] }   # PUT replaces, POST appends
DELETE             /api/v3-alpha/<resource>/{id}/tags/{tag}
GET / POST         /api/v3-alpha/<resource>/{id}/files      (multipart: file, title)
GET                /api/v3-alpha/<resource>/{id}/files/{file_id}/download
```

Authorization for a sub-resource is inherited from its parent object.

More worked request/response pairs live in [`api_v3_examples.md`](https://github.com/DefectDojo/django-DefectDojo/blob/dev/api_v3_examples.md)
at the repository root.

## CSV export

Every top-level list endpoint has a CSV projection at `GET /<resource>/export.csv` (findings, assets,
organizations, engagements, tests, users, locations — `locations` keeps its superuser gate):

```
GET /api/v3-alpha/findings/export.csv?severity=High&o=-date&fields=id,title,impact
```

- **Same filter contract as the list.** `export.csv` takes the identical filters, `o=` ordering,
  `q=` free-text search, and `?fields=` (including the detail opt-up) as `GET /<resource>`. It has
  **no pagination**: the response is the whole filtered, authorized set. `expand`, `include`,
  `limit`, `offset`, `pagination`, and `cursor` are not applicable and return `400`
  `application/problem+json`.
- **Streamed attachment.** The response is `Content-Type: text/csv; charset=utf-8` with
  `Content-Disposition: attachment; filename="<resource>-export.csv"`, streamed row-by-row so memory
  and query count stay bounded regardless of the number of rows.
- **Row cap.** If the filtered set exceeds `DD_API_V3_EXPORT_MAX_ROWS` (default 100 000) the request
  returns `400` asking you to narrow the filter — the export is **never silently truncated**.
- **Column flattening.** The columns are the JSON row's fields (in schema order, restricted to your
  `?fields=` selection):
  - a `{id, name}` ref becomes two columns `<key>_id` and `<key>_name` (a location ref adds
    `<key>_type`);
  - `tags` becomes a single semicolon-joined column;
  - datetimes are ISO-8601 `Z`, dates `YYYY-MM-DD`, booleans lowercase `true`/`false`, and `null`
    renders as an empty cell.
  A zero-row export still returns the header row.
- **Spreadsheet-injection hardening.** Any cell whose text starts with `=`, `+`, `-`, `@`, or a tab
  is prefixed with a single quote so spreadsheet software does not evaluate it as a formula.

## Known alpha gaps

The alpha delivers the contract and the seven read/write surfaces above. These are **known,
deliberate** gaps — several exist so the alpha stayed additive and reviewable:

- **Note side-effects have v2 parity in the alpha.** Creating a note via `POST .../{id}/notes` fires
  the same side-effects as the v2 notes endpoints, per resource: findings get JIRA comment sync (on a
  linked issue, else the finding-group issue), `last_reviewed` / `last_reviewed_by` stamping, and
  `@mention` notifications; engagements and tests get `@mention` notifications only (their v2
  endpoints have neither JIRA sync nor `last_reviewed` stamping).
- **Finding writes mirror the v2 serializer, not the UI view.** The finding create/update service
  reproduces the v2 API serializer semantics (JIRA push, risk acceptance, vuln-ids/CWE). UI-only
  behaviors are deferred: auto-mitigation when `active` flips off, false-positive-history
  reactivation, `last_reviewed` stamping, finding-group push, GitHub sync, and JIRA link/unlink.
- **No bulk or workflow actions yet.** No bulk operations, no workflow actions
  (`close`/`request_review`/`mark_duplicate`), no aggregation/chart endpoints, no saved views, no
  XLSX export (CSV export **is** available — see above), no delete-impact preview. These are recorded
  as explicit post-alpha work items in the plan's backlog.

## Platform limitations (not v3 gaps)

- **Locations are URL-only.** Only the `URL` location subtype has a persistable model in the
  codebase today; `Code` and `Dependency` location data is dropped on import until their models
  land. This is a limitation of the underlying Location subsystem, not of the v3 API — v3 simply
  refuses to advertise location types the backend cannot store. Locations are **read-only** in the
  alpha (lifecycle is import-driven).

## Design decisions to be aware of

- **Counts above the cap are estimates — by design.** Below `COUNT_CAP` (default 10,000) `count` is
  exact. Above it, `count` is the Postgres planner's row estimate for the filtered query, clamped to
  ≥ CAP+1 and flagged `"count_exact": false` in `meta`. This is the documented count strategy
  (bounded cost on unbounded tables), not a deficiency awaiting a fix. Estimates depend on planner
  statistics and may drift; when you page-jump near an estimated end you may get an empty `results`
  with `next: null`.

See `API_V3_PLAN.md` in the repository for the full contract specification and decision log.
