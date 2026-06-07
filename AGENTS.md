# DefectDojo Development Guide

## Project Overview

DefectDojo is a Django application (`dojo` app) for vulnerability management. The codebase is undergoing a modular reorganization to move from monolithic files toward self-contained domain modules.

## Module Reorganization

### Reference Pattern: `dojo/url/`

All domain modules should match the structure of `dojo/url/`. This is the canonical example of a fully reorganized module.

```
dojo/{module}/
├── __init__.py       # import dojo.{module}.admin  # noqa: F401
├── models.py         # Domain models, constants, factory methods
├── admin.py          # @admin.register() for the module's models
├── services.py       # Business logic (no HTTP concerns)
├── queries.py        # Complex DB aggregations/annotations
├── signals.py        # Django signal handlers
├── [manager.py]      # Custom QuerySet/Manager if needed
├── [validators.py]   # Field-level validators if needed
├── [helpers.py]      # Async task wrappers, tag propagation, etc.
├── ui/
│   ├── __init__.py   # Empty
│   ├── forms.py      # Django ModelForms
│   ├── filters.py    # UI-layer django-filter classes
│   ├── views.py      # Thin view functions — delegates to services.py
│   └── urls.py       # URL routing
└── api/
    ├── __init__.py   # path = "{module}"
    ├── serializer.py # DRF serializers
    ├── views.py      # API ViewSets — delegates to services.py
    ├── filters.py    # API-layer filters
    └── urls.py       # add_{module}_urls(router) registration
```

### Architecture Principles


**services.py is the critical layer**: Both `ui/views.py` and `api/views.py` call `services.py` for business logic. Services accept domain objects and primitives — never request/response objects, forms, or serializers.

**Backward-compatible re-exports**: When moving code out of monolithic files (`dojo/models.py`, `dojo/forms.py`, `dojo/filters.py`, `dojo/api_v2/serializers.py`, `dojo/api_v2/views.py`), always leave a re-export at the original location:
```python
from dojo.{module}.models import {Model}  # noqa: F401 -- backward compat
```
Never remove re-exports until all consumers are updated in a dedicated cleanup pass.

### Current State

Modules in various stages of reorganization:

| Module | models.py | services.py | ui/ | api/ | Status |
|--------|-----------|-------------|-----|------|--------|
| **url** | In module | N/A | Done | Done | **Complete** |
| **location** | In module | N/A | N/A | Done | **Complete** |
| **product_type** | In dojo/models.py | Missing | Partial (views at root) | In dojo/api_v2/ | Needs work |
| **test** | In dojo/models.py | Missing | Partial (views at root) | In dojo/api_v2/ | Needs work |
| **engagement** | In dojo/models.py | Partial (32 lines) | Partial (views at root) | In dojo/api_v2/ | Needs work |
| **product** | In dojo/models.py | Missing | Partial (views at root) | In dojo/api_v2/ | Needs work |
| **finding** | In dojo/models.py | Missing | Partial (views at root) | In dojo/api_v2/ | Needs work |

### Monolithic Files Being Decomposed

These files still contain code for multiple modules. Extract code to the target module's subdirectory and leave a re-export stub.

- `dojo/models.py` (4,973 lines) — All model definitions
- `dojo/forms.py` (4,127 lines) — All Django forms
- `dojo/filters.py` (4,016 lines) — All UI and API filter classes
- `dojo/api_v2/serializers.py` (3,387 lines) — All DRF serializers
- `dojo/api_v2/views.py` (3,519 lines) — All API viewsets

---

## Reorganization Playbook

When asked to reorganize a module, follow these phases in order. Each phase should be independently verifiable.

### Phase 0: Pre-Flight (Read-Only)

Before any changes, identify all code to extract:

```bash
# 1. Model classes and line ranges in dojo/models.py
grep -n "class {Model}" dojo/models.py

# 2. Form classes in dojo/forms.py
grep -n "class.*{Module}" dojo/forms.py
grep -n "model = {Model}" dojo/forms.py

# 3. Filter classes in dojo/filters.py
grep -n "class.*{Module}\|class.*{Model}" dojo/filters.py

# 4. Serializer classes
grep -n "class.*{Model}" dojo/api_v2/serializers.py

# 5. ViewSet classes
grep -n "class.*{Model}\|class.*{Module}" dojo/api_v2/views.py

# 6. Admin registrations
grep -n "admin.site.register({Model}" dojo/models.py

# 7. All import sites (to verify backward compat)
grep -rn "from dojo.models import.*{Model}" dojo/ unittests/

# 8. Business logic in current views
# Scan dojo/{module}/views.py for: .save(), .delete(), create_notification(),
# jira_helper.*, dojo_dispatch_task(), multi-model workflows
```

### Phase 1: Extract Models

1. Create `dojo/{module}/models.py` with the model class(es) and associated constants
2. Create `dojo/{module}/admin.py` with `admin.site.register()` calls (remove from `dojo/models.py`)
3. Update `dojo/{module}/__init__.py` to `import dojo.{module}.admin  # noqa: F401`
4. Add re-exports in `dojo/models.py`
5. Remove original model code (keep re-export line)

**Import rules for models.py:**
- **Prefer string FK refs to break circular imports.** Convert EVERY ForeignKey/ManyToMany/OneToOne whose target is NOT a class being moved into a string ref `"dojo.<Model>"` (e.g. `models.ForeignKey(Engagement, ...)` → `models.ForeignKey("dojo.Engagement", ...)`). This lets the extracted `models.py` carry ZERO top-level `from dojo.models import ...`, which is what actually prevents circular imports. String refs produce identical migrations (Django resolves via the app registry) — `makemigrations --check` must still say "No changes detected".
- References AMONG the classes being moved together also use string refs, for uniformity and to avoid in-file ordering issues.
- Downward/other dojo references inside METHOD bodies: lazy imports inside the method.
- Shared utilities (`copy_model_util`, `_manage_inherited_tags`, `get_current_date`, `tomorrow`, etc.): import from `dojo.models`. CAVEAT: if a utility is used as a class-body field default (e.g. `default=get_current_date`), it must be imported (not redefined locally) so its `__module__` stays `dojo.models` — otherwise migration serialization changes and `makemigrations` flags a diff. These utils are defined early in `dojo.models` (before the re-export that loads your module), so a top-level `from dojo.models import get_current_date, tomorrow, copy_model_util` resolves correctly despite the partial circular load.
- Do NOT set `app_label` in Meta — all models inherit `dojo` app_label automatically

**Lint conventions (the repo pre-commit ruff is strict — match exactly):**
- Method-body lazy imports need `# noqa: PLC0415 -- lazy import, avoids circular dependency`.
- Mid-file / non-top re-exports in `dojo/models.py` need `# noqa: E402`, plus `# noqa: F401` ONLY on names not referenced elsewhere in `dojo/models.py` (a name still used by a remaining class body must NOT get F401).
- Self-check before committing: `/home/valentijn/.local/bin/ruff check --config ruff.toml <files>` (ruff is a host binary, NOT in the uwsgi container). Never let `ruff --fix` wrap a re-export into a parenthesized multiline — shorten the comment instead.

**Re-export placement:** use ONE consolidated re-export block per module, placed at the earliest moved class's original position. A name referenced in a class-body FK at load-time must be re-exported BEFORE that line.

**Constants:** single-source module-level constants in the extracted module and re-export from `dojo/models.py` (done for `IMPORT_ACTIONS`, `ENGAGEMENT_STATUS_CHOICES`). Do not duplicate.

**Watch for load-bearing imports:** some imports in `dojo/models.py` exist for side effects, not the imported name (e.g. `from dojo.utils import parse_cvss_data` transitively registers `dojo.location` models for `apps.py:ready()`). If you remove the last consumer of such an import, keep it as a re-export or `apps.py` breaks.

**Verify** (runs in docker; model imports need `manage.py shell -c`, not bare `python -c`):
```bash
docker compose exec -T uwsgi python manage.py check
docker compose exec -T uwsgi python manage.py makemigrations --check --dry-run   # must say "No changes detected"
docker compose exec -T uwsgi python manage.py shell -c "from dojo.{module}.models import {Model}; print('ok')"
docker compose exec -T uwsgi python manage.py shell -c "from dojo.models import {Model}; print('ok')"
```

### Phase 2: Extract Services

**This phase is conditional.** If the module's views are pure CRUD (form save/delete, simple field add/remove) with none of the "belongs in services" items below, there is NO `services.py` — skip the phase (the `url`/`location` reference modules have none). Don't invent a service just to have one.

Create `dojo/{module}/services.py` with business logic extracted from UI views.

**What belongs in services.py:**
- State transitions (close, reopen, status changes)
- Multi-step creation/update workflows
- External integration calls (JIRA, GitHub)
- Notification dispatching
- Copy/clone operations
- Bulk operations
- Merge operations

**What stays in views:**
- HTTP request/response handling
- Form instantiation and validation
- Serialization/deserialization
- Authorization checks (`@user_is_authorized`, `user_has_permission_or_403`)
- Template rendering, redirects
- Pagination, breadcrumbs

**Service function pattern:**
```python
def close_engagement(engagement: Engagement, user: User) -> Engagement:
    engagement.active = False
    engagement.status = "Completed"
    engagement.save()
    if jira_helper.get_jira_project(engagement):
        dojo_dispatch_task(jira_helper.close_epic, engagement.id, push_to_jira=True)
    return engagement
```

Update UI views and API viewsets to call the service instead of containing logic inline.

### Phase 3: Extract Forms to `ui/forms.py`

1. Create `dojo/{module}/ui/__init__.py` (empty)
2. Create `dojo/{module}/ui/forms.py` — move form classes from `dojo/forms.py`
3. Add re-exports in `dojo/forms.py`

### Phase 4: Extract UI Filters to `ui/filters.py`

1. Create `dojo/{module}/ui/filters.py` — move module-specific filters from `dojo/filters.py`
2. Shared base classes (`DojoFilter`, `DateRangeFilter`, `ReportBooleanFilter`) stay in `dojo/filters.py`. **Keep the original base class** (`class XFilter(DojoFilter)`) — do NOT switch to `FilterSet` to dodge an import.
3. **Circular-import caveat**: a re-export in `dojo/filters.py` (`from dojo.{module}.ui.filters import XFilter`) while `ui/filters.py` imports `DojoFilter` back from `dojo.filters` creates a real cycle (fails when `ui/filters.py` loads first). Resolve per the re-export rule below — usually: **drop the `dojo/filters.py` re-export** when the filter's only consumer is the module's own view, and import the filter directly from `dojo.{module}.ui.filters` in that view (matches the `url` module).

> **Re-export decisions (Phases 3,4,6,8) — decide per symbol, by actual remaining consumers:**
> - `grep -rn` the symbol across `dojo/` and `unittests/` first. Account for multi-line `from x import (\n  ...\n)` blocks — a one-line grep misses them.
> - If a symbol is still referenced by code that REMAINS in the monolith (e.g. `ProductTypeSerializer` used by `ReportGenerateSerializer` in `api_v2/serializers.py`) → **keep** the re-export (`# noqa: E402` + `F401` as needed).
> - If the ONLY consumers are code you are moving/updating anyway (the module's own views/tests) → **omit** the re-export and point those consumers at the new path. This is required when a re-export would cycle (filter↔`dojo.filters`, `api_v2.views`↔`{module}.api.views`).
> - After dropping any re-export, run the module's real unit tests (not just `manage.py check`) — `check` won't catch a broken import in a test module.

### Phase 5: Move UI Views/URLs into `ui/`

1. Move `dojo/{module}/views.py` -> `dojo/{module}/ui/views.py`
2. Move `dojo/{module}/urls.py` -> `dojo/{module}/ui/urls.py`
3. Update URL imports:
   - product: update `dojo/asset/urls.py`
   - product_type: update `dojo/organization/urls.py`
   - others: update the include in `dojo/urls.py`

### Phase 6: Extract API Serializers to `api/serializer.py`

1. Create `dojo/{module}/api/__init__.py` with `path = "{module}"`
2. Create `dojo/{module}/api/serializer.py` — move from `dojo/api_v2/serializers.py`
3. Add re-exports in `dojo/api_v2/serializers.py`

### Phase 7: Extract API Filters to `api/filters.py`

1. Create `dojo/{module}/api/filters.py` — move `Api{Model}Filter` from `dojo/filters.py`
2. Add re-exports

### Phase 8: Extract API ViewSets to `api/views.py`

1. Create `dojo/{module}/api/views.py` — move from `dojo/api_v2/views.py`
2. Add re-exports in `dojo/api_v2/views.py`

### Phase 9: Extract API URL Registration

1. Create `dojo/{module}/api/urls.py`:
   ```python
   from dojo.{module}.api import path
   from dojo.{module}.api.views import {ViewSet}

   def add_{module}_urls(router):
       router.register(path, {ViewSet}, path)
       return router
   ```
2. Update `dojo/urls.py` — replace `v2_api.register(...)` with `add_{module}_urls(v2_api)`

**Preserve the exact route and basename** from the original `v2_api.register(...)` call. They often differ (e.g. route `product_types`, `basename="product_type"`); `path` in `api/__init__.py` should be the route string, and pass `basename=` explicitly if the original did. Changing either breaks DRF URL reversing and the API tests. Verify with `reverse('{basename}-list')`.

### After Each Phase: Verify

```bash
docker compose exec -T uwsgi python manage.py check
docker compose exec -T uwsgi python manage.py makemigrations --check --dry-run
# Tests run via the wrapper (NOT pytest/manage.py test directly); tee to capture output:
./run-unittest.sh --test-case unittests.{relevant_test_module} 2>&1 | tee /tmp/test.log
```

---

## Cross-Module Dependencies

The model hierarchy is: Product_Type -> Product -> Engagement -> Test -> Finding

Extract in this order (top to bottom) so that upward FKs can import from already-extracted modules. The recommended order is: product_type, test, engagement, product, finding.

For downward references (e.g., Product_Type's cached properties querying Finding), always use lazy imports:
```python
@cached_property
def critical_present(self):
    from dojo.models import Finding  # lazy import
    return Finding.objects.filter(test__engagement__product__prod_type=self, severity="Critical").exists()
```

---

## Key Technical Details

- **Single Django app**: Everything is under `app_label = "dojo"`. Moving models to subdirectories does NOT require migration changes.
- **Model discovery**: Triggered by `__init__.py` importing `admin.py`, which imports `models.py`. This is the same chain `dojo/url/` uses.
- **Signal registration**: Handled in `dojo/apps.py` via `import dojo.{module}.signals`. Already set up for test, engagement, product, product_type.
- **Watson search**: Uses `self.get_model("Product")` in `apps.py` — works via Django's model registry regardless of file location.
- **Admin registration**: Currently at the bottom of `dojo/models.py` (lines 4888-4973). Must be moved to `{module}/admin.py` and removed from `dojo/models.py` to avoid `AlreadyRegistered` errors.
