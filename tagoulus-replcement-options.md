# Tagulous Replacement Options

## Context

DefectDojo uses [django-tagulous](https://github.com/radiac/django-tagulous) (forked locally at `/home/valentijn/django-tagulous/`) for tagging on 9 models. Library is unmaintained upstream. Local fork carries 1 commit (Django 5.2 deserializer monkeypatch). Performance is the primary pain point — signal-driven count maintenance and per-row M2M sync on every save.

## Current State

### Tagulous usage in DefectDojo

- **9 TagFields**, all flat, all `force_lowercase=True`. No trees. No `SingleTagField`. No `max_count`.
- Models: `Product`, `Engagement`, `Test`, `Finding`, `Endpoint`, `FindingTemplate`, `AppAnalysis`, `Objects_Product`, `Location`.
- **`tag.count`** unused outside tests. Pure overhead.
- **`_inherited_tag_names` JSONField** already replaced 5 inherited M2Ms in migration `0265`. Pattern proven internally.
- **`dojo/tag_utils.py`** (526 LOC) bypasses tagulous internals for bulk ops. Depends on `tag_options`, `related_model`, `remote_field.through`.
- **9 tag tables + 9 through-tables + 5 JSON columns** active.

### Tagulous internals (perf hotspots)

- **Signals fire on every write**: `pre_save`, `post_save`, `pre_delete`, `post_delete`. `post_save` always calls `reload()` + `add()`/`remove()` even when tags unchanged.
- **`update_count()`**: full requery per tag on raw deserialization.
- **Increment/decrement** uses F-expressions per tag, then refreshes.
- **No setting** to disable count maintenance.
- **Library size**: ~4500 LOC total, ~1800 LOC core. Vendorable.

### Features used vs unused

| Feature | Used? |
|---|---|
| Flat M2M tags | Yes |
| `force_lowercase` | Yes |
| Custom DRF parsing (comma/quoted) | Yes |
| Autocomplete widget | Yes (admin + UI) |
| Tag trees (`tree=True`) | No |
| `SingleTagField` | No |
| `max_count` | No |
| `protect_initial` / `protect_all` | No |
| `tag.count` (public) | No |
| Merge/rename admin | Minimal |

## Options Ranked

### Option A — JSONField only (drop M2M entirely) — best long-term

Store `tags = JSONField(default=list)` per object. Index via GIN (Postgres) or functional index. Lookups via `tags__contains=[name]`.

**Pros**
- No through-tables. No tag table. No signals. No count drift.
- Insert/update = single column write. Bulk = `bulk_update`.
- Matches doc-store model. Inheritance is already JSON.
- GIN-backed lookup fast on Postgres.
- Eliminates 9 tag tables + 9 through-tables. Major schema simplification.

**Cons**
- No central tag registry. Autocomplete needs `DISTINCT jsonb_array_elements` or small `Tag(name)` registry refreshed async.
- Rename tag = `UPDATE WHERE tags @> ['old']` per affected table. Heavier than tagulous merge.
- MySQL/MariaDB JSON perf weaker than Postgres. Check support matrix (DefectDojo supports both).
- Large data migration: 9 fields × all rows. Batched backfill required.
- Serializer/form/widget rewrite. Lose autocomplete widget unless rebuilt.
- Breaks consumers assuming M2M shape (admin filters, pghistory proxies, external plugins).

### Option B — Vendor tagulous, gut it — best short-term

Copy `tagulous/` into `dojo/tagulous/`. Strip:
- `count` field + all `increment`/`decrement`/`try_delete`/`update_count`
- tree code (`TagTreeModel`, ~150 LOC)
- `pre_delete`/`post_delete` for `SingleTagField` (unused)
- raw=True `update_count` loop (signal hotspot)
- `protect_initial`/`protect_all` paths (unused)

Keep: parser, manager, descriptor, autocomplete widget, migration ops.

**Pros**
- ~50% LOC reduction. Owned. No upstream coupling.
- Removes biggest perf hits (count maintenance, raw deserialization recount).
- Migrations stay valid (same model shape). Zero data migration.
- `dojo/tag_utils.py` keeps working unchanged.
- Unblocks Django 5.2+ permanently.

**Cons**
- Still M2M-shaped. Per-write signal overhead still exists, just lighter.
- ~2000 LOC owned by team.
- Doesn't fix root cause (signal-driven sync). Trims fat only.

### Option C — Hybrid: JSON denorm + keep M2M

Add `tag_names JSONField` alongside existing M2M. Reads/serializers/filters use JSON. M2M kept for admin/legacy.

**Pros**: incremental. Low risk per step. Can drop M2M later.

**Cons**: data duplication on writes. Two sources of truth = sync bugs. Worst-of-both during transition.

### Option D — Keep fork as-is, add knobs

Add to fork: `count_disabled=True` option, batch signal mode, skip-redundant-add path.

**Pros**: minimal change.

**Cons**: still upstream-shaped library no one else maintains. `tag_utils.py` still depends on internals. Doesn't solve root issue.

### Option E — Build new lib ("if we built it today")

Tiny library `django-jsontags`:
- `JSONTagField` = JSONField subclass
- Validators (lowercase, charset, max length)
- Manager-like `.add()/.remove()/.set()` via descriptor
- Lookup helpers wrapping `__contains` for cross-DB compat
- Optional async-refreshed `Tag(name, last_seen)` registry for autocomplete
- Postgres GIN auto-index hint
- DRF field + Form widget (Select2 fed by registry)
- ~500 LOC. No signals. No counts. No trees.

Open-source as replacement for tagulous. Solves real ecosystem pain.

## Recommendation

**Two-step plan**:

### Step 1 (now, 1–2 sprints): Option B

Vendor tagulous into `dojo/tagulous/`, strip count + tree + raw-recount + unused protect paths. Removes signal hotspots without data migration. Unblocks Django 5.2+. Keeps `tag_utils.py` working. Low risk.

Deliverables:
- `dojo/tagulous/` with stripped code
- Pin replaces `tagulous` import path
- Drop `count` column via single migration
- Benchmark: import workflow + bulk-tag ops before/after

### Step 2 (next quarter): Option A

Migrate to JSONField, model by model, starting with **Endpoint** (highest write volume from imports) then **Finding** (largest table). Per model:

1. Add `tag_names JSONField` + GIN index (Postgres) / functional index (MySQL)
2. Backfill in batches via management command
3. Switch reads to JSON (services, serializers, filters, search)
4. Switch writes to JSON via service layer (`tag_utils.py` becomes thin wrapper)
5. Validate parity for one release
6. Drop M2M + tag table

### Step 3 (optional, after dogfooding): Option E

Extract `django-jsontags` library from internal code. Free byproduct of step 2. Open-source as tagulous successor.

## Key Risks

- **DB matrix**: confirm Postgres + MySQL JSON ops. DefectDojo supports both. Test on MariaDB minimum supported version.
- **Autocomplete UX**: registry table refresh strategy must be designed before any model flips.
- **Audit log (pghistory)**: tags currently tracked via through-table proxy models. JSON column tracks differently. Verify history continuity.
- **External integrations**: any plugin/parser/API consumer assuming M2M shape breaks. Grep `dojo_pro` + external projects.
- **Search ranking**: full-text/Watson over tag names — confirm GIN-backed `@>` matches current ranking behavior.
- **Admin filters**: Django admin `list_filter` on tags loses M2M widget. Replace or drop.
- **Bulk-import perf regression**: validate `tag_utils.py` paths still beat naive M2M during step 1, before step 2 begins.

## Open Questions

- Drop MariaDB/MySQL support tier for tag-heavy queries, or build cross-DB lookup helper?
- Move tag registry refresh to Celery task or DB trigger?
- Keep merge/rename admin UI or accept SQL-level rename procedure?
- Include `Tag.description`/`Tag.color` metadata fields in registry, or keep tags pure strings?

---

## Addendum — Design notes from follow-up review

### `raw=True` on `post_save`

Django passes `raw=True` when the save originates from `loaddata` (fixture/dump deserialization). Tagulous treats this as "data injected directly into DB, internal counters stale" and calls `tag.update_count()` per tag — full `COUNT(*)` requery for every tag on every fixture-loaded row. Catastrophic on large dumps. Stripping this branch is one of the cheap wins in Option B.

### Field-change detection (Option A signal)

Codebase already uses `from fieldsignals import pre_save_changed` (see [dojo/finding/helper.py:16](dojo/finding/helper.py#L16)). No need for `django-model-utils` `FieldTracker` or self-rolled mixin.

Hook shape:

```python
from fieldsignals import pre_save_changed

@receiver(pre_save_changed, sender=Finding, fields=['tags'])
def on_tags_changed(sender, instance, changed_fields, **kwargs):
    field = Finding._meta.get_field('tags')
    old, new = changed_fields[field]
    added = set(new or []) - set(old or [])
    removed = set(old or []) - set(new or [])
    ...
```

### Batch context manager

Mirror existing `dojo/tag_inheritance.py:batch()` pattern. Thread-local flag suppresses dispatch, accumulates diff, flushes on exit:

```python
_batch_state = threading.local()

@contextmanager
def batch_tag_writes():
    _batch_state.active = True
    _batch_state.added = set()
    _batch_state.removed = set()
    try:
        yield
    finally:
        added, removed = _batch_state.added, _batch_state.removed
        _batch_state.active = False
        if added or removed:
            transaction.on_commit(lambda: registry_upsert.delay(list(added), list(removed)))
```

Importer wraps bulk loop in `with batch_tag_writes():`. Single dispatch instead of N.

### Edge cases for any signal-driven path

- **`bulk_update`/`bulk_create` skip signals.** Bulk paths must call registry update explicitly. `dojo/tag_utils.py` is the right seam — already centralizes bulk.
- **Queryset `.update()` skips signals too.** Same fix.
- **Transaction rollback**: always use `transaction.on_commit(...)` so dispatched task only fires on committed write. Critical to avoid registry pollution from rolled-back imports.
- **Race vs nightly GC**: GC must check current state at run-time, not trust `last_seen` alone. Otherwise concurrent writes lose entries.

---

## Tag Registry — three implementation flavors

The "registry" = table backing autocomplete and (optionally) per-tag counts. Three valid shapes, ranked.

### Reg-1 — Maintained table + signals

`Tag(name PK, last_seen)` updated by `pre_save_changed` signal. Nightly GC removes orphans.

- **Pros**: cheap read (`name ILIKE 'crit%' LIMIT 20`), realtime visibility of new tags.
- **Cons**: drift under bulk paths, signal plumbing, batch hooks, `on_commit`, GC job. Same maintenance disease as `tag.count` today, in miniature.

### Reg-2 — On-demand DISTINCT (no registry)

```sql
SELECT DISTINCT jsonb_array_elements_text(tags) AS name
FROM finding
ORDER BY name LIMIT 20;
```

UNION across tagged tables for global autocomplete.

- **Pros**: zero maintenance. Always current. No signals.
- **Cons**: GIN index does **not** accelerate `DISTINCT jsonb_array_elements_text` — it accelerates containment, not distinct extraction. Needs expression index or `pg_trgm` on extracted values. Slow on Finding/Endpoint without help.
- **Verdict**: viable for small tables only (Product, Engagement). Not for hot tables.

### Reg-3 — Materialized view ★ recommended

```sql
CREATE MATERIALIZED VIEW dojo_tag_names AS
SELECT DISTINCT name FROM (
    SELECT jsonb_array_elements_text(tags) AS name FROM finding
    UNION
    SELECT jsonb_array_elements_text(tags) FROM product
    UNION ...
) t;
CREATE UNIQUE INDEX ON dojo_tag_names(name);
CREATE INDEX ON dojo_tag_names USING gin(name gin_trgm_ops);
```

Refresh `CONCURRENTLY` on cron (every 5 min). Optional write-path fast-path: `INSERT ... ON CONFLICT DO NOTHING` on tag-create so new tags autocomplete immediately. View still rebuilds nightly to GC removed names.

- **Pros**: zero signal coupling. Fast autocomplete (trigram). Converges. Single bg job. No per-write maintenance.
- **Cons**: stale window for *removed* tags (acceptable — autocomplete tolerates ghosts). Postgres-only.
- **MariaDB equivalent**: regular table + scheduled `INSERT ... ON DUPLICATE KEY UPDATE` from `SELECT DISTINCT JSON_EXTRACT(...)`. Same shape, manual refresh.

### Recommendation

**Reg-3** with optional insert-only fast-path on tag create. Reg-1 only wins if realtime *removal* visible in autocomplete is required (it isn't). Reg-2 only wins on tiny tables.

---

## Counts later (if/when needed) — three flavors

Same lesson as registry: don't bring M2M back. Counts fit in registry table or a derived view.

### Count-1 — Incremental column on registry

`ref_count INTEGER` updated by signal diff. Atomic `F('ref_count') ± 1`.

- **Pros**: O(diff) per write. Realtime.
- **Cons**: drifts under bulk + rollback. Same maintenance disease as today's `tag.count`.

### Count-2 — On-demand recount

```sql
SELECT COUNT(*) FROM finding WHERE tags @> '["critical"]'::jsonb;
```

GIN index makes containment fast even on 1M rows.

- **Pros**: always correct. No coupling.
- **Cons**: O(matching rows) per query unless cached.

### Count-3 — Materialized view ★ recommended if counts ever needed

```sql
CREATE MATERIALIZED VIEW dojo_tag_counts AS
SELECT 'finding' AS scope, tag, COUNT(*) AS n
FROM finding, jsonb_array_elements_text(tags) AS tag
GROUP BY tag
UNION ALL ...;
```

Refresh nightly or on demand.

- **Pros**: correct, fast read, no coupling, multi-scope in one query.
- **Cons**: stale until refresh. Postgres CONCURRENTLY needs unique index. MariaDB needs equivalent table + cron.

### Recommendation

Start with **no count column at all**. `tag.count` was unused for years. If a real consumer appears (tag cloud, reports), add **Count-3**. Skip Count-1 — its maintenance cost is exactly what Option A is escaping.

---

## Updated decision summary

- **Field-change detection**: `fieldsignals.pre_save_changed`. Already in tree.
- **Registry**: Reg-3 (materialized view + optional insert-only fast-path).
- **Counts**: skip until proven need. Then Count-3.
- **Batch path**: thread-local context manager + `transaction.on_commit` + explicit hooks in `tag_utils.py` bulk methods.
- **M2M not needed for any of the above.**
