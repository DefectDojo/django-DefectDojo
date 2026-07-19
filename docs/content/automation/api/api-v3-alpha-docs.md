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

The alpha covers seven objects — `product_type`, `product`, `engagement`, `test`, `finding`,
`location`, `user` — plus a single consolidated `import` endpoint. Everything else stays on v2 until
v3 reaches parity.

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
- OpenAPI schema: **`/api/v3-alpha/openapi.json`** (`info.version = 3.0.0-alpha`)

The "try it out" flow works with your logged-in session, or paste a token (see below).

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

### Refs

Every relation renders by default as a closed ref:

```jsonc
{ "id": 42, "name": "Q3 Pentest" }
```

The relation key tells you the type, so refs carry no `type` field — **except** location refs, which
add `"type": "<location_type>"`. On writes you reference a relation by its **integer id**
(`"test": 9`); on reads you get a ref back. This asymmetry is intentional.

### `?expand=`, `?fields=`, `?include=`

| Param | Does | Example |
|---|---|---|
| `?expand=` | Swaps a ref for the target's slim object **inline** and drives the queryset. Comma-separated dotted paths, budget-guarded. | `?expand=test.engagement,reporter` |
| `?fields=` | Allowlist of fields to return (`id` always included). The picker facility. | `?fields=id,title,severity` |
| `?include=counts` | Adds severity/status totals over the **filtered, authorized** queryset to `meta`, in one query — no second round-trip. | `?include=counts` |

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

| Object | v2 | v3 (alpha) | Notes |
|---|---|---|---|
| Product type | `/api/v2/product_types/` | `/api/v3-alpha/product_types` | CRUD (PATCH-only partial update) |
| Product | `/api/v2/products/` | `/api/v3-alpha/products` | CRUD |
| Engagement | `/api/v2/engagements/` | `/api/v3-alpha/engagements` | CRUD |
| Test | `/api/v2/tests/` | `/api/v3-alpha/tests` | CRUD |
| Finding | `/api/v2/findings/` | `/api/v3-alpha/findings` | CRUD + `?expand=`, `?include=counts` |
| Location | `/api/v2/endpoints/` (legacy `Endpoint`) | `/api/v3-alpha/locations` | **Concept change** (see below); read-only in alpha |
| User | `/api/v2/users/` | `/api/v3-alpha/users` | Read + self; admin-only writes |
| Import | `/api/v2/import-scan/` + `/api/v2/reimport-scan/` | `/api/v3-alpha/import` | **Consolidated** — one endpoint, `mode=auto\|import\|reimport` |

### Locations replace endpoints

v3 does not expose the legacy `Endpoint` model. A finding relates to **locations** many-to-many, with
the status (`Active` / `Mitigated` / `FalsePositive` / `RiskAccepted` / `OutOfScope`) carried on the
edge. Slim findings carry `locations_count`; the full edge list is a sub-resource:

- `GET /api/v3-alpha/findings/{id}/locations` → `{ location: {id, name, type}, status, audit_time, auditor }`
- `GET /api/v3-alpha/products/{id}/locations` → `{ location: {id, name, type}, status }`

### Import in one call

`POST /api/v3-alpha/import` (multipart) covers all three flows. `mode=auto` resolves an existing
target via product/engagement names; `import` and `reimport` are explicit. **Destructive flags are
never implied by mode** — if you omit `close_old_findings`, the importer default applies and the
response echoes the effective value:

```jsonc
{ "mode_resolved": "reimport", "test": { "id": 9, "name": "ZAP Scan" },
  "statistics": { "new": 4, "reactivated": 1, "closed": 2, "untouched": 37 },
  "close_old_findings": true }
```

## One way to do notes, tags and files

Where v2 accreted per-resource actions and mechanisms, v3 has **one generic sub-resource** for each,
attached to every resource whose model stores it (notes/files: finding, engagement, test; tags:
those plus product):

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

## Known alpha gaps

The alpha delivers the contract and the seven read/write surfaces above. These are **known,
deliberate** gaps — several exist so the alpha stayed additive and reviewable:

- **Note side-effects are not fired yet.** Creating a note via `POST .../{id}/notes` persists the
  note but does **not** yet trigger the side-effects the v2 UI/serializer path does — JIRA comment
  sync, `last_reviewed` / `last_reviewed_by` stamping, and `@mention` notifications. These arrive on
  the post-alpha convergence track.
- **Finding writes mirror the v2 serializer, not the UI view.** The finding create/update service
  reproduces the v2 API serializer semantics (JIRA push, risk acceptance, vuln-ids/CWE). UI-only
  behaviors are deferred: auto-mitigation when `active` flips off, false-positive-history
  reactivation, `last_reviewed` stamping, finding-group push, GitHub sync, and JIRA link/unlink.
- **Locations are URL-only.** Only the `URL` location subtype persists today; `Code` and
  `Dependency` subtypes are dropped on import until their models land. Locations are **read-only** in
  the alpha (lifecycle is import-driven).
- **No bulk or workflow actions yet.** No bulk operations, no workflow actions
  (`close`/`request_review`/`mark_duplicate`), no aggregation/chart endpoints, no saved views, no
  CSV export, no delete-impact preview. Cursor pagination and background-import jobs are reserved in
  the grammar (they return `400 "not yet available"`) but not implemented.
- **Counts above the cap are estimates.** Below `COUNT_CAP` (default 10,000) `count` is exact. Above
  it, `count` is the Postgres planner's row estimate for the filtered query, clamped to ≥ CAP+1 and
  flagged `"count_exact": false` in `meta`. Estimates depend on planner statistics and may drift;
  when you page-jump near an estimated end you may get an empty `results` with `next: null`.

See `API_V3_PLAN.md` in the repository for the full contract specification and decision log.
