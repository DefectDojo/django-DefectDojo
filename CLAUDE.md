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
- Upward FKs (e.g., Test -> Engagement): import from `dojo.models` if not yet extracted, or `dojo.{module}.models` if already extracted
- Downward references (e.g., Product_Type querying Finding): use lazy imports inside method bodies
- Shared utilities (`copy_model_util`, `_manage_inherited_tags`, `get_current_date`, etc.): import from `dojo.models`
- Do NOT set `app_label` in Meta — all models inherit `dojo` app_label automatically

**Verify:**
```bash
python manage.py check
python manage.py makemigrations --check
python -c "from dojo.{module}.models import {Model}"
python -c "from dojo.models import {Model}"
```

### Phase 2: Extract Services

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
2. Shared base classes (`DojoFilter`, `DateRangeFilter`, `ReportBooleanFilter`) stay in `dojo/filters.py`
3. Add re-exports in `dojo/filters.py`

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

### After Each Phase: Verify

```bash
python manage.py check
python manage.py makemigrations --check
python -m pytest unittests/ -x --timeout=120
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
