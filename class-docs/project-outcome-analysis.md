# Project Outcome Analysis

**Project:** [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) (fork: [tlmcguire/django-DefectDojo](https://github.com/tlmcguire/django-DefectDojo))
**Course:** CSCI 360 — Software Architecture, Security, and Testing
**Student:** Tyler McGuire
**Tool used:** Claude Code (Anthropic), run directly in the cloned fork directory.

DefectDojo is a Django application for tracking application-security findings across
products, engagements, and scans, with a REST API, Celery-based async processing, and
integrations for dozens of scanning tools.

## Screenshots

1. *Fork page* — `tlmcguire/django-DefectDojo` showing "forked from DefectDojo/django-DefectDojo".
2. *Terminal* — `git remote -v` and `git log --oneline -5` from the local clone.
3. *AI assistant* — Claude Code answering "list the top-level directories in this repository and describe what each one contains" using this project's real directory names.

*(See the "How to capture the three screenshots" section at the end for what actually goes here — inserted by hand before publishing.)*

## The Seventeen Outcomes

### 1. Iteration with an agile approach / a resilient OO analysis and design process (Unified Process)

DefectDojo's own development process is the evidence, not just its code. [`dojo/db_migrations/`](../dojo/db_migrations) holds roughly 290 sequential migration files (`0001_initial.py` through `0291_dojometa_location_product.py` as of this writing), each a small, independently reviewable schema increment rather than one big upfront design — pairs like `0287_vulnerability_id_entity_tables.py` followed by `0288_backfill_vulnerability_id_entities.py` show the classic "add schema, then backfill data" two-step of iterative delivery. This isn't accidental: [`readme-docs/RELEASING.md`](../readme-docs/RELEASING.md) documents a formal two-track release cadence (monthly feature releases from `dev` via `release/x.y.z` branches, weekly bugfix releases from `bugfix`), and [`readme-docs/CONTRIBUTING.md`](../readme-docs/CONTRIBUTING.md) describes `django-linear-migrations` with a `max_migration.txt` tracking file specifically to keep many people's iterative schema changes from colliding. `dojo/__init__.py` currently pins `__version__ = "3.2.300"` — this project genuinely ships incremental design changes on a near-continuous cadence, which is exactly the kind of resilient, incremental redesign the Unified Process asks us to evaluate.

### 2. Work in teams to design software

The upstream project's real process is well-documented team practice: [`.github/CODEOWNERS`](../.github/CODEOWNERS) assigns `/docs/content/` to specific reviewers and all other code to a separate pair of maintainers, [`.github/pull_request_template.md`](../.github/pull_request_template.md) standardizes what every contributor must fill out, and [`readme-docs/CONTRIBUTING.md`](../readme-docs/CONTRIBUTING.md) has explicit "Submission Pre-Approval" and "Code Review Process" sections. `.github/workflows/unit-tests.yml` gates merges behind required CI checks in a merge queue, so no single person's change lands without review and a passing suite. That said, this is a weaker fit for *my own* work specifically: this assignment is individual, and my commits to my fork won't themselves go through that review process unless a later assignment has me open a PR upstream or work with classmates directly. The evidence for outcome 2 is currently "I can point at how the real maintainers do it," not "I have done it myself" — worth revisiting if a team assignment comes later in the semester.

### 3. Analyze a software application problem with use cases

The API layer reads directly as a set of use cases. `class ImportScanView` and `class ReImportScanView` in [`dojo/api_v2/views.py`](../dojo/api_v2/views.py) are two distinct actor-facing operations: "import a brand-new scan" versus "reimport/update an existing scan against history." `close_old_findings` in [`dojo/importers/base_importer.py`](../dojo/importers/base_importer.py) is its own use case — "findings a rescan no longer reports should be automatically mitigated." `class CeleryViewSet` exposes yet another: "check the status of an in-flight async import job." These map cleanly onto a use-case diagram with an actor (API client / CI pipeline) and a handful of named use cases.

### 4. Produce a conceptual domain model with UML class diagram, associations, roles, multiplicities

`class Finding(BaseModel)` in [`dojo/finding/models.py:55`](../dojo/finding/models.py) is the center of the model: a many-to-many `endpoints` association to `Endpoint`, a many-to-one `test` association to `Test`, and a self-referential `duplicate_finding = ForeignKey("self")` for the duplicate-cluster relationship. `class Finding_Group` (same file, ~line 1537) is a many-to-many aggregation over `Finding`. `class Engagement(BaseModel)` in [`dojo/engagement/models.py:44`](../dojo/engagement/models.py) has a many-to-one association to `Product`. `class Endpoint` in [`dojo/endpoint/models.py:104`](../dojo/endpoint/models.py) has the reciprocal many-to-many back to `Finding`. That's real 1-to-many and many-to-many multiplicities, straight out of the actual schema, to draw into a class diagram rather than invent.

### 5. Use System Sequence Diagrams to illustrate operations

The import operation is a clean actor → boundary → controller → service chain: an API client hits `ImportScanView` ([`dojo/api_v2/views.py`](../dojo/api_v2/views.py)), which delegates to `DefaultImporter.process_scan` ([`dojo/importers/default_importer.py:93`](../dojo/importers/default_importer.py)), an implementation of the abstract contract defined by `BaseImporter` ([`dojo/importers/base_importer.py:72`](../dojo/importers/base_importer.py), with `process_scan`, `process_findings`, `close_old_findings`, and `process_scan_file`). That's a direct System Sequence Diagram: `:Client -> :ImportScanView -> :DefaultImporter -> :Parser -> :Finding(db)`.

### 6. Produce operation contracts

`validate_scan_date` in [`dojo/api_v2/serializers.py:609`](../dojo/api_v2/serializers.py) and five separate `validate(self, data)` methods (lines 224, 279, 588, 1001, 1162 in the same file) express explicit preconditions — correct `scan_type`, a valid date, required fields present — that must hold before an import or update is allowed to proceed. These read almost directly as the precondition clauses of an operation contract; the corresponding postconditions are the resulting `Finding`/`Test` state changes performed by the importer once validation passes.

### 7. Logical architectures and message passing among components

`docker-compose.yml` lays the logical architecture out directly as named services: `nginx`, `uwsgi` (the Django app tier), `celerybeat` + `celeryworker` (the async task tier), `postgres` (data tier), and `valkey` (Redis-compatible broker) — a textbook layered architecture. Message passing between components happens two ways in code: Celery tasks in [`dojo/tasks.py`](../dojo/tasks.py) (e.g. `async_dupe_delete`, `jira_status_reconciliation_task`) for cross-process asynchronous work, and Django signal receivers in [`dojo/finding/helper.py`](../dojo/finding/helper.py) (e.g. `pre_save_finding_status_change`, `finding_pre_delete`/`finding_post_delete`) for decoupled in-process notification between components.

### 8. Explain the nature and use of software patterns, with a code example

**Factory/Registry:** [`dojo/tools/factory.py`](../dojo/tools/factory.py) keeps a `PARSERS` dict and `register_parser()`/`get_parser()` functions, auto-discovering every `dojo/tools/<name>/parser.py` at startup so a brand-new scanner integration self-registers without anyone editing `factory.py`. **Observer/Strategy:** [`dojo/notifications/helper.py`](../dojo/notifications/helper.py) defines a `NotificationManagerHelpers` base with polymorphic subclasses `SlackNotificationManger`, `MSTeamsNotificationManger`, `EmailNotificationManger`, `WebhookNotificationManger`, `AlertNotificationManger`, all invoked uniformly through `NotificationManager.create_notification()` — a second real, walkable example with actual code behind it.

### 9. Basics of software object design and responsibilities/collaborations (GRASP)

**Information Expert:** `Finding.status()` ([`dojo/finding/models.py:1037`](../dojo/finding/models.py)) computes the finding's own derived state from its own fields, rather than pushing that logic into a view. **Controller:** `ImportScanView`/`ReImportScanView` stay thin and delegate the actual work to `DefaultImporter` — a domain-service Controller collaborator. **Pure Fabrication / Low Coupling:** [`dojo/finding/helper.py`](../dojo/finding/helper.py) holds deduplication and grouping logic (`create_finding_group`, `group_findings_by`) in its own module instead of bloating the `Finding` model or its serializer.

### 10. Use UML activity diagrams to analyze and model processes

`DefaultReImporter.process_scan` ([`dojo/importers/default_reimporter.py:91`](../dojo/importers/default_reimporter.py)) branches into `process_matched_finding` → `process_matched_special_status_finding` / `process_matched_mitigated_finding` / `process_matched_active_finding` / `process_finding_that_was_not_matched` — a real decision-branch process ready to diagram. The bulk-delete path in [`dojo/finding/helper.py`](../dojo/finding/helper.py) (`prepare_duplicates_for_delete` → `resolve_inbound_duplicate_references` → `_bulk_delete_findings_internal`) is a second clean multi-step activity with genuine forks.

### 11. Use UML state diagrams to analyze and model states

`Finding` carries boolean state fields `active`, `verified`, `false_p`, `duplicate`, `out_of_scope`, `risk_accepted`, and `is_mitigated`, which `Finding.status()` (line 1037) reduces to named composite states — Active, Verified, Mitigated, False Positive, Duplicate, Risk Accepted — a direct state machine to diagram. `Engagement.status` ([`dojo/engagement/models.py:66`](../dojo/engagement/models.py)) uses `ENGAGEMENT_STATUS_CHOICES` (line 34) for its own lifecycle states.

### 12. Demonstrate basic design principles

**Open/Closed:** [`dojo/tools/factory.py`](../dojo/tools/factory.py)'s auto-discovery means adding a new scanner never requires editing the factory itself. **Separation of Concerns:** models ([`dojo/finding/models.py`](../dojo/finding/models.py)), serializers ([`dojo/api_v2/serializers.py`](../dojo/api_v2/serializers.py)), and business logic ([`dojo/finding/helper.py`](../dojo/finding/helper.py)) are deliberately kept in separate modules instead of fat models or views. **Single Responsibility:** [`dojo/authorization/`](../dojo/authorization) is split into eight single-purpose files — `roles_permissions.py`, `authorization.py`, `query_filters.py`, `url_permissions.py`, `api_permissions.py`, `template_filters.py`, `serializer_guards.py`, `middleware.py`.

### 13. Explain and implement test-driven development

[`unittests/`](../unittests) holds 442 `test_*.py` files, kept entirely separate from application code in `dojo/`, with a shared base in [`unittests/dojo_test_case.py`](../unittests/dojo_test_case.py) (`DojoTestCase`, `DojoAPITestCase`). `.github/workflows/unit-tests.yml` runs this suite as a required "Unit Tests Complete" check in the merge queue. A suite this large and this tightly wired into CI is strong evidence I can both read existing tests for TDD-style examples and add my own new tests that follow the established `DojoTestCase` pattern.

### 14. Exhibit a basic working knowledge of GUI development using an IDE

[`dojo/templates/`](../dojo/templates) holds the Django server-rendered template layer (`dojo/templates/dojo/`, `.../partials/`, `.../snippets/`, plus dedicated issue-tracker and login templates), and `dojo/static/dojo/` holds `css/`, `js/`, `img/`, and `fonts/`. This is a genuine but honestly weak fit: it's classic server-rendered Django + Bootstrap/jQuery UI, not the kind of IDE-driven GUI-builder work (Swing, WinForms, a modern SPA component framework) this outcome probably has in mind. It's enough to demonstrate *basic* GUI development, but it won't be the strongest example in my portfolio.

### 15. Produce a Software Architecture Document

[`docs/content/get_started/open_source/architecture.md`](../docs/content/get_started/open_source/architecture.md) is a dedicated architecture page for the open-source edition (there's also a separate cloud-architecture page for the paid product), backed by `readme-docs/RELEASING.md`, `DOCKER.md`, and `KUBERNETES.md` for supporting operational detail. This is also a weaker fit as-is: the existing material is informal — closer to a deployment README than a formal Software Architecture Document with explicit views (logical, process, deployment, etc.). It's a real starting point I can extend, not a document I can simply point at and call done.

### 16. Write and present orally analyses of topics in software analysis and design

Not something the codebase itself can provide evidence for — this outcome is demonstrated through the Part 5 presentation, not a file citation. I'll cover this project, its two or three strongest outcomes (likely 8, 13, and 17), and its two or three weakest (14, 15, and 2), and be ready to open the actual files behind every claim above.

### 17. Incorporate misuse/abuse cases in the system design

This is one of the project's strongest outcomes. [`dojo/authorization/api_permissions.py`](../dojo/authorization/api_permissions.py) defines fine-grained per-resource permission classes — `UserHasFindingPermission`, `UserHasImportPermission`, `UserHasEngagementPermission` — and [`dojo/authorization/roles_permissions.py`](../dojo/authorization/roles_permissions.py)'s `class Permissions(IntEnum)` (line 69) enumerates granular actions (`View`, `Add`, `Edit`, `Delete`, `Import`, `StaffOnly`, `SuperuserOnly`), each encoding an explicit misuse boundary — who is and isn't allowed to do what to a given resource. [`SECURITY.md`](../SECURITY.md) documents the HackerOne-based disclosure process and explicitly asks researchers to refrain from denial-of-service testing, and [`.dryrunsecurity.yaml`](../.dryrunsecurity.yaml) wires an automated security reviewer into every pull request. Genuinely better misuse/abuse-case support out of the box than most course projects will have.

## Honest weak spots

Three outcomes are a real stretch for this project as it stands today, and I'd rather flag that now than discover it in Week 11:

- **Outcome 2 (team-based design):** the *project's* process is team-based; *my* work on my fork, for this assignment, is not. I have upstream's practice to point at, not my own experience yet.
- **Outcome 14 (GUI/IDE development):** server-rendered Django templates satisfy the letter of the outcome but not really its spirit of hands-on IDE GUI-builder work.
- **Outcome 15 (Software Architecture Document):** the existing architecture docs are closer to informal deployment notes than a formal SAD — I'll be writing most of this one myself rather than pointing at something that already exists.

## AI Use Log

**Tool:** Claude Code (Anthropic), run directly inside this cloned fork at `/Users/tyler/Projects/django-DefectDojo`, with shell, file-edit, and read access to the whole repository.

**What I asked it to do, and what it did:**

1. Verified the fork/remote setup was already correct (`origin` → `tlmcguire/django-DefectDojo`, `upstream` → `DefectDojo/django-DefectDojo`) by running `git remote -v` and cross-checking with `gh repo view --json isFork,parent`, rather than assuming.
2. Checked whether the fork's wiki was actually initialized (not just the `has_wiki` flag) by attempting to clone `django-DefectDojo.wiki.git`, which confirmed no wiki pages exist yet.
3. Created a `coursework/csci360-project-outcome-analysis` branch off `master` rather than committing coursework directly to the branch that mirrors the current release line.
4. Created the top-level `class-docs/` directory (avoiding `/docs`, which is DefectDojo's own Hugo documentation site) to hold this file and future diagrams.
5. Ran a dedicated research pass across the codebase — `dojo/finding/models.py`, `dojo/engagement/models.py`, `dojo/importers/`, `dojo/tools/factory.py`, `dojo/notifications/helper.py`, `dojo/authorization/`, `.github/`, `docker-compose.yml`, and the `unittests/` tree — to find real, citable evidence for each of the seventeen outcomes, then independently spot-checked the highest-stakes citations (parser factory, `Finding` model fields, `Permissions` enum, migration count, Docker service names, `CODEOWNERS`) with direct `grep`/`find` commands before writing anything down.
6. Wrote the seventeen outcome paragraphs above, each anchored to specific, verified file paths, class names, and function names rather than generic claims.
7. Flagged three outcomes (2, 14, 15) as genuinely weak fits, with the specific reasoning behind each, instead of claiming full support across the board.

**Net effect:** every citation in this document points at a real file and was checked against this repository before being written down, not generated from general knowledge of what a project "like DefectDojo" might contain.
