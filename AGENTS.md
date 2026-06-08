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
| **product_type** | In module | N/A | Done | Done | **Complete** (#14970) |
| **test** | In module | N/A | Done | Done | **Complete** (#14971) |
| **engagement** | In module | In module | Done | Done | **Complete** (#14972) |
| **product** | In module | N/A | Done | Done | **Complete** (#14973) |
| **finding** | In module | N/A (helper.py) | Done | Done | **Complete** (#14974); CWE+Burp pending |
| **peripheral (×18)** | In dojo/models.py | — | Partial/none | Partial/none | **Phase 10** (PRs #6–10, see below) |

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
3. Re-export ONLY the serializers still referenced by code REMAINING in `api_v2/serializers.py` (e.g. one nested by `ReportGenerateSerializer` / used in a `RiskAcceptance` representation). Serializers consumed only by the viewset are imported by their new path in Phase 8, so omit those re-exports.

   **EXCEPTION — prefetcher discovery (re-export the FULL moved ModelSerializer set):** `dojo/api_v2/prefetch/prefetcher.py` builds its model→serializer map via `inspect.getmembers(sys.modules["dojo.api_v2.serializers"], ...)`. Any moved `ModelSerializer` that drops out of `api_v2/serializers.py`'s module members disappears from that map, so prefetch breaks (e.g. `test_detail_prefetch` / `test_list_prefetch` fail with `'<field>' not found`) — and `manage.py check` does NOT catch it; only the `test_rest_framework` prefetch tests do. So re-export the ENTIRE set of moved `ModelSerializer`s (not just the ReportGenerate-nested ones), even nested/sub serializers with no other consumer. This re-export block is byte-identical module membership → zero behavior change. (Pure `serializers.Serializer` subclasses that aren't tied to a model and aren't referenced elsewhere can still be omitted.) This bit the finding module (18 serializers); revisit earlier modules if their prefetch tests ever regress.

**Cycle-break for serializers that reference api_v2 serializers** (matches `dojo/test/api/serializer.py`, `dojo/engagement/api/serializer.py`): a moved serializer cannot import `NoteSerializer`/`FileSerializer`/`TagListSerializerField` etc. from `dojo.api_v2.serializers` at module level — that cycles once `api_v2/serializers.py` re-imports your serializer. Convert class-body field assignments (`tags = TagListSerializerField(...)`, `notes = NoteSerializer(many=True)`) into a lazy `get_fields()` override that imports inside the method (`# noqa: PLC0415`); `build_relational_field` lazy-imports the same way. The extracted module then carries ZERO top-level `dojo.api_v2.serializers` import.

**`@extend_schema_field` decorators referencing api_v2 serializers also cycle** (their argument is evaluated eagerly at class-body load). A class-body `@extend_schema_field(RiskAcceptanceSerializer)` / `@extend_schema_field(BurpRawRequestResponseSerializer)` cannot stay. Drop the decorator and reapply the override at the bottom of the module via `drf_spectacular.utils.set_override(Cls.method, "field", LazyImportedSerializer)` inside a small `_apply_schema_overrides()` that lazy-imports the api_v2 serializer (`# noqa: PLC0415`). This preserves the generated schema with no top-level api_v2 reference. (Decorators whose argument is one of the MOVED serializers in the same file are fine as-is.)

### Phase 7: Extract API Filters to `api/filters.py`

1. Create `dojo/{module}/api/filters.py` — move `Api{Model}Filter` from `dojo/filters.py`
2. Add re-exports

### Phase 8: Extract API ViewSets to `api/views.py`

1. Create `dojo/{module}/api/views.py` — move from `dojo/api_v2/views.py`
2. Do NOT re-export the viewset in `dojo/api_v2/views.py` — it would cycle (`api_v2.views` ↔ `{module}.api.views`, because the viewset imports its base classes back from `api_v2.views`). Update the consumers instead: the `dojo/urls.py` registration (Phase 9) and `unittests/test_rest_framework.py`, which imports viewsets by name (a dropped re-export there is an ImportError that `manage.py check` won't catch — only the test run does).

**Viewset import pattern (matches `dojo/test/api/views.py`, `dojo/engagement/api/views.py`):** `from dojo.api_v2.views import DojoModelViewSet, PrefetchDojoModelViewSet, report_generate, schema_with_prefetch` — base classes and helpers stay in the monolith. Requalify every `serializers.X` reference that stays in `api_v2` to `api_v2_serializers.X` via `from dojo.api_v2 import serializers as api_v2_serializers`; import the MOVED serializers by name from `dojo.{module}.api.serializer`. PRESERVE active class decorators such as `@extend_schema_view(**schema_with_prefetch())` — they are easy to drop when copying a viewset and silently change the generated schema. After moving, prune the now-unused engagement-specific imports left behind in `api_v2/views.py` (filter, services, queries, models) — ruff flags them.

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

**When copying a class/function out, capture through to the next top-level `class`/dedent.** A fixed-line-window read can silently truncate a long class (trailing fields + `Meta` + `__init__`), yielding a partial copy that still imports cleanly but drops behavior. Confirm the last line of the source class before deleting it from the monolith.

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

---

## Phase 10: Peripheral Model Modules — 10-PR Stack Continuation

> **This section is the complete, self-contained brief for a fresh agent session (auto mode) to finish the reorganization.** The 5 core hierarchy modules (`product_type`, `test`, `engagement`, `product`, `finding`) are DONE — they are the templates. What remains is moving the ~45 *peripheral* model classes still defined in `dojo/models.py` into their domain modules, each as a **full vertical slice** (all 9 phases), reusing the playbook above.

### Goal & scope

`dojo/models.py` is now ~2,254 lines and still **defines** these peripheral model classes. Move each into its module (most module dirs already exist with `views.py`/`urls.py`/helpers but NO `models.py`/`admin.py` — only `dojo/url/` and `dojo/location/` are complete-with-models templates). Leave backward-compat re-exports in every monolith (`dojo/models.py`, `forms.py`, `filters.py`, `api_v2/serializers.py`, `api_v2/views.py`) per the rules above.

**Decisions already locked with the user (do NOT relitigate):**
- **Full vertical slice per module** (Phases 1–9), not models-only. Skip a phase only when the module genuinely has no code for it (e.g. no API serializer/viewset exists → no `api/` layer; no module-specific form → no `ui/forms.py`). Follow the "Phase 2 is conditional" / re-export-by-actual-consumer rules above.
- **These models STAY in `dojo/models.py`** (no module worth creating — do NOT extract): `DojoMeta`, `Network_Locations`, `Sonarqube_Issue`, `Sonarqube_Issue_Transition`, `Check_List`, `Testing_Guide_Category`, `Testing_Guide`, `Language_Type`, `Languages`, `App_Analysis`. Leave them untouched.
- **`CWE` + `BurpRawRequestResponse` fold into `finding`** (they are finding-domain), and are done FIRST on the EXISTING finding PR (#14974), not a new PR.

### The 10-PR stack

The 5 core PRs already exist (stacked, merge bottom-up): `dev ← #14970 product_type ← #14971 test ← #14972 engagement ← #14973 product ← #14974 finding`. **The new work CONTINUES this stack on top of #14974.** All branches and PRs follow the same conventions as the existing 5.

| PR | Branch (head) | Base | Contents |
|----|---------------|------|----------|
| 1–5 | existing | existing | DONE: product_type, test, engagement, product, finding |
| **5 (#14974)** | `reorg/finding-models` | `reorg/product-models` | **ADD `CWE` + `BurpRawRequestResponse` to `dojo/finding/`** (full slice). Existing PR — do NOT create a new one. |
| **6** | `reorg/peripheral-user` | `reorg/finding-models` | **Bundle A**: `user` (`Dojo_User`, `UserContactInfo`, `Contact`) + `system_settings` (`System_Settings`) |
| **7** | `reorg/peripheral-tools-endpoint` | `reorg/peripheral-user` | **Bundle B**: `endpoint` (`Endpoint_Params`, `Endpoint_Status`, `Endpoint`) + `tool_type` (`Tool_Type`) + `tool_config` (`Tool_Configuration`, + admin classes `ToolConfigForm_Admin`/`Tool_Configuration_Admin`) + `tool_product` (`Tool_Product_Settings`, `Tool_Product_History`) |
| **8** | `reorg/peripheral-survey-benchmark` | `reorg/peripheral-tools-endpoint` | **Bundle C**: `survey` (`Question`, `TextQuestion`, `Choice`, `ChoiceQuestion`, `Engagement_Survey`, `Answered_Survey`, `General_Survey`, `Answer`, `TextAnswer`, `ChoiceAnswer`) + `benchmark` (`Benchmark_Type`, `Benchmark_Category`, `Benchmark_Requirement`, `Benchmark_Product`, `Benchmark_Product_Summary`) |
| **9** | `reorg/peripheral-notes-files` | `reorg/peripheral-survey-benchmark` | **Bundle D**: `notes` (`NoteHistory`, `Notes`) + `note_type` (`Note_Type`) + `file_uploads` (`UniqueUploadNameProvider`, `FileUpload`, `FileAccessToken`) + `reports` (`Report_Type`) + `risk_acceptance` (`Risk_Acceptance`) |
| **10** | `reorg/peripheral-misc` | `reorg/peripheral-notes-files` | **Bundle E**: `regulations` (`Regulation`) + `banner` (`BannerConf`) + `announcement` (`Announcement`, `UserAnnouncement`) + `development_environment` (`Development_Environment`) + `object` (`Objects_Review`, `Objects_Product`) |

**Bundle order is by FK direction**: `user` first (`Dojo_User` is an FK target almost everywhere); everything else references already-moved or string-ref'd models. Inside a bundle, FKs between same-bundle models are real class refs; FKs to anything OUTSIDE the bundle become string refs `"dojo.<Model>"` (per the string-FK rule above — this keeps the extracted `models.py` free of top-level `from dojo.models import`).

### Stack & PR mechanics (locked with user)

- **Branches live on the `upstream` remote** (`git@github.com:DefectDojo/django-DefectDojo.git`), exactly like the existing 5 (their head branches are on upstream, e.g. `upstream/reorg/finding-models`). Push each new branch to `upstream`, and **force-push with `--force-with-lease`** on cascade (`git push --force-with-lease upstream <branch>:<branch>`).
- **The 5 new PRs are DRAFT PRs.** Create with `gh pr create --draft --repo DefectDojo/django-DefectDojo --base <prev-branch> --head <this-branch>`.
- Each new branch is created from its predecessor's tip: `git checkout -b reorg/peripheral-user reorg/finding-models`, etc. Merge bottom-up.
- **PR descriptions**: every PR in the stack (all 10) must include a stack map listing all 10 PRs in order with checkboxes and the bottom-up merge note, so reviewers see the whole picture. Summary section only — NO test-plan section (see CLAUDE.local.md / PR rules). Format PR URLs as markdown links. Read an existing body with `gh pr view <N> --json body -q '.body'` before editing; edit via `--body-file` or the REST `gh api -X PATCH` path (inline `--body` silently fails on this repo).
- **Cascade after editing a lower branch** (e.g. this AGENTS.md commit on #14970): `git rebase --onto <new-parent> <old-parent-sha> <branch>` up the chain, then force-push all with `--force-with-lease`. AGENTS.md edits always land on the bottom branch (#14970) and cascade.

### Per-module execution = the 9-phase playbook above

For EACH module in a bundle, run **Phase 0 pre-flight first** (the grep block above) to discover its exact forms/filters/serializers/viewsets/urls/admin/signals/consumers — do NOT trust a memorized list. Then Phases 1–9. Reference complete templates: `dojo/url/`, `dojo/location/` (models), and `dojo/finding/`, `dojo/product/`, `dojo/test/`, `dojo/engagement/` (full API+UI slices). Verify gates after each phase (`manage.py check`, `makemigrations --check --dry-run`, `./run-unittest.sh --test-case unittests.<module> 2>&1 | tee /tmp/test.log`). All gates run in docker (`docker compose exec -T uwsgi ...`); model imports need `manage.py shell -c`.

### Model line ranges in `dojo/models.py` (snapshot — re-grep before editing; line numbers shift as you extract)

- **CWE** 1027–1031 · **BurpRawRequestResponse** 1563–1575 → `finding` (PR #14974)
- **Dojo_User** 174–209 · **UserContactInfo** 211–234 · **Contact** 605–612 · **System_Settings** 236–595
- **Tool_Type** 940–949 · **Tool_Configuration** 951–979 · **ToolConfigForm_Admin/Tool_Configuration_Admin** 981–1010 · **Endpoint_Params** 1033–1039 · **Endpoint_Status** 1041–1093 · **Endpoint** 1095–1470 · **Tool_Product_Settings** 1765–1777 · **Tool_Product_History** 1779–1785
- **Benchmark_Type** 1890–1905 · **Benchmark_Category** 1907–1921 · **Benchmark_Requirement** 1923–1939 · **Benchmark_Product** 1941–1957 · **Benchmark_Product_Summary** 1959–1989 · **Question** 1992–2012 · **TextQuestion** 2014–2024 · **Choice** 2026–2039 · **ChoiceQuestion** 2041–2058 · **Engagement_Survey** 2060–2076 · **Answered_Survey** 2078–2101 · **General_Survey** 2107–2123 · **Answer** 2126–2138 · **TextAnswer** 2140–2149 · **ChoiceAnswer** 2151–2253
- **Note_Type** 614–623 · **NoteHistory** 625–636 · **Notes** 638–669 · **UniqueUploadNameProvider** 108–135 · **FileUpload** 671–749 · **FileAccessToken** 1679–1703 · **Report_Type** 751–753 · **Risk_Acceptance** 1577–1677
- **Regulation** 136–168 · **Announcement** 1713–1725 · **UserAnnouncement** 1727–1730 · **BannerConf** 1732–1763 · **Development_Environment** 1472–1481 · **Objects_Review** 1829–1835 · **Objects_Product** 1837–1861

### Module-specific gotchas (beyond the generic playbook)

- **`Question` / `Answer` (survey)**: base classes are defined inside a `with warnings.catch_warnings(): ...` block (polymorphic-model deprecation suppression). PRESERVE that block structure when moving to `dojo/survey/models.py` — don't flatten it.
- **survey & benchmark have NO serializers/viewsets in `api_v2`** (verified). So Bundle C likely has no `api/` layer — skip Phases 6–9 for those modules (confirm with Phase 0). They DO have UI views/urls/forms/filters.
- **`Benchmark_Requirement` → M2M `CWE`**: `CWE` moves to `finding` in PR #14974 (lands lower in the stack), so by the time Bundle C runs, use string ref `"dojo.CWE"` (the `dojo.models` re-export stays valid). Same for any other `CWE` reference.
- **`Risk_Acceptance`**: M2M `accepted_findings`→Finding, FK `owner`→Dojo_User, M2M `notes`→Notes — all cross-bundle → string refs. `dojo/risk_acceptance/` already has `api.py`/`helper.py`/`queries.py`/`signals.py` but no `models.py`; reconcile `api.py` vs the playbook's `api/` dir layout.
- **`Endpoint`**: references `Dojo_User`, `Finding`, `Product`, `Endpoint_Status` — string-ref everything except same-bundle `Endpoint_Params`/`Endpoint_Status`. `dojo/endpoint/` already has `queries.py`/`utils.py`/`signals.py`.
- **`tool_config` admin**: `ToolConfigForm_Admin` (a `forms.ModelForm`) and `Tool_Configuration_Admin` (an `admin.ModelAdmin`) currently sit in `dojo/models.py` — move them to `dojo/tool_config/admin.py` (form + admin), not `models.py`.
- **`CWE` / `BurpRawRequestResponse` are heavily imported** (20+ files across `dojo/` and `unittests/`, including tool parsers for CWE and importers for Burp). Run the Phase 0 consumer grep (`grep -rn "import.*\bCWE\b" dojo/ unittests/`, same for `BurpRawRequestResponse`) and rely on the `dojo.models` re-export for external consumers — only repoint finding's own code.
- **Shared bases (the `FindingTagStringFilter` trap)**: before moving any form/filter, grep for subclasses/consumers OUTSIDE the module. If a base form/filter is also used by a model staying in `dojo/models.py` or another module, KEEP it in the monolith and import it, rather than moving + back-importing (which cycles). The prefetcher full-re-export rule (Phase 6) applies to any moved `ModelSerializer`.

### After the stack is built

Update the **Current State** table above (mark the newly-completed modules **Complete**), and update the monolith line counts in "Monolithic Files Being Decomposed" (they are stale — `dojo/models.py` is ~2,254 lines now, not 4,973).
