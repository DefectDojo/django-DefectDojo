---
name: defectdojo-dev
description: Develop, test, and validate DefectDojo changes end to end against a local Docker stack — bring the app up on localhost:8080, reproduce a bug on the target branch before fixing it, write behavioral unit tests that fail without the fix, drive the UI with the Playwright MCP, and fetch an API token to exercise the REST API. The same review lenses (scalability, performance, memory, DB resourcing, query design, security, DRF serializer exposure) let it double as an inbound PR reviewer, with a dedicated checklist for infra/Helm/deployment PRs. Use when developing or testing a change, reproducing or fixing a bug, writing a regression test, validating a fix, or reviewing any DefectDojo PR/branch (app, API, or Helm chart).
---

# Develop, test, and review DefectDojo changes

This is the primary workflow for building and verifying a change in this repo, and
secondarily for reviewing someone else's PR. DefectDojo is a Django app (server-rendered
templates, not a SPA) run via Docker Compose, with a Postgres DB and a Valkey broker. Work
the loop below against a **running local stack** — do not reason about behavior from the
code alone when you can exercise it.

Read `AGENTS.md` first for the branch/release-line policy: bug fixes target `bugfix`,
features target `dev`, and `master` is off-limits without explicit confirmation (the
`.claude/hooks/branch-guard.sh` hook enforces this). Put the work on the right branch
before editing.

## Inputs

- **What you're working on** (one of): a change/feature you're building, a bug or issue to
  reproduce and fix, or a PR number / branch / URL to review.
- **Focus area** (optional): a specific concern lens to emphasize (e.g. "just the query
  performance", "security only").

## Helper scripts

Both live in this skill directory. `chmod +x` them once if needed.

- **`get-api-token.sh`** — fetches a REST API token so you can test API endpoints.
  `POST`s to `/api/v2/api-token-auth/` with a username/password and prints the raw token.
  Defaults: user `admin`, password `admin`, base URL `http://localhost:8080` (override with
  `DD_USER` / `DD_PASSWORD` / `DD_BASE_URL`). Use the token as `Authorization: Token <t>`.
  If token auth is disabled, get one from the UI at `/api/key-v2` instead.
- **`run-tests.sh`** — thin wrapper over the repo's sanctioned `./run-unittest.sh` that tees
  output to a log. Pass a fully-qualified test target:
  `./run-tests.sh unittests.tools.test_acunetix_parser.TestAcunetixParser`. Requires the dev
  stack to be up. Do **not** call `pytest` or `manage.py test` directly — the wrapper is the
  supported path (runs `--keepdb -v2`, checks compose first).

## Steps

1. **Bring the stack up (dev mode).** Dev mode is what gives you `admin`/`admin` and
   hot-reload:
   ```bash
   ./docker/setEnv.sh dev
   docker compose up -d
   ```
   The UI is at `http://localhost:8080` (login `/login`). Creds are `admin`/`admin` **in dev
   mode only**. If someone ran a plain `docker compose up` instead, the admin password is
   random — read it with `docker compose logs initializer | grep "Admin password:"`, or
   reset via `docker compose exec uwsgi ./manage.py changepassword admin`.

2. **Reproduce first (bugs).** Before changing anything, prove the bug exists **on the
   target/base branch** (the one the fix will land on). Capture the concrete failure — a
   screenshot, a stack trace, a wrong value, a 500. Reproduce through the real surface:
   - **UI:** drive it with the Playwright MCP — navigate to `http://localhost:8080/login`,
     log in, and walk the exact flow. Expect full-page navigations and CSRF-protected forms
     (hidden `csrfmiddlewaretoken` inputs); auth is a session cookie, so there's no
     client-side router to wait on.
   - **API:** grab a token with `get-api-token.sh` and hit `/api/v2/...` with
     `Authorization: Token <t>`.
   A bug you cannot reproduce is not yet understood — say so rather than guessing at a fix.

3. **Develop / apply the change.** Make the fix or feature on the correct branch. The dev
   stack bind-mounts the source with autoreload, so edits to Python are picked up live —
   re-exercise the same UI/API path from step 2 to confirm the behavior actually changed.

4. **Write behavioral unit tests.** Every fix gets a test that **fails without the change and
   passes with it** — that's what stops the regression from coming back. Prefer asserting on
   observable behavior (returned values, DB state, response codes, finding counts/attributes)
   over implementation details or line coverage. Tests live under `unittests/`
   (`unittests/tools/` for parsers). Run them the sanctioned way:
   ```bash
   ./run-tests.sh unittests.<module>.<TestClass>
   ```
   Confirm the test is real by checking it **fails on the pre-fix code** (stash the fix, run,
   see red), then passes with the fix.

   For a **query-count / performance** change, the guard is
   `unittests/test_importers_performance.py`, which asserts exact query and task counts. If
   your change legitimately shifts those counts, regenerate them with
   `python scripts/update_performance_test_counts.py` (add `--verify` to check) and commit the
   result — don't hand-edit the expected numbers. A prime way to prove a query fix is to assert
   the generated SQL no longer contains the offending `LEFT OUTER JOIN` / `GROUP BY` (see
   `build_count_subquery` in `dojo/query_utils.py`, the correlated-subquery pattern the product
   list views use to avoid GROUP-BY fan-out).

5. **Self-check with the concern lenses.** Before calling the change done, run it through
   each lens below. These are the axes that matter in this codebase — map each finding to a
   concrete line:
   - **Scalability / query design:** N+1 queries and missing `select_related` /
     `prefetch_related`; unbounded querysets materialized with `list()` or iterated in full;
     `.count()` or queries inside loops; filtering/ordering on unindexed columns; work that
     grows with the number of findings/products (DefectDojo instances routinely hold millions
     of findings).
   - **Performance:** synchronous work that belongs in a Celery task; repeated recomputation
     that should be cached; expensive serialization on hot paths.
   - **Memory:** reading an entire uploaded scan file into memory at once; loading a whole
     queryset (or a full serialized payload) into RAM instead of streaming/paginating; large
     in-memory dedup structures.
   - **DB resourcing / migrations:** schema migrations that lock or rewrite large tables;
     missing indexes for new query patterns; data migrations that run row-by-row in the
     request/boot path; migrations that aren't reversible. Never edit an existing migration —
     add a new one, and commit `dojo/db_migrations/max_migration.txt` (django-linear-migrations).
   - **Security:** authorization checks (`user_has_permission` / the authorization decorators)
     on every new view/endpoint — DefectDojo is multi-tenant, so an object read/write must be
     scoped to the requesting user's products; injection (raw SQL, `format`/f-strings into
     queries); SSRF and XML entity expansion (parsers must use `defusedxml`, never `lxml`).
   - **Serializer exposure (DRF):** mass-assignment and secret leakage both hide in the
     `Meta`. `fields = "__all__"` **and** `exclude = (...)` are equally risky — both
     auto-expose any *new* model field, so `exclude` is not automatically safe; check what a
     new field would surface. Credential-adjacent fields (API keys, tokens, the linked config
     object's secret) must be `write_only=True` so they're never serialized into a GET
     response, and related-object querysets on writable fields should be scoped to what the
     requesting user may reference. Confirm no secret is echoed back and nothing sensitive
     lands in logs.

6. **Run tests + guards.** Run the affected test module(s), plus the guards CI enforces so a
   green local run matches CI:
   ```bash
   docker compose exec uwsgi python manage.py makemigrations --check --dry-run
   docker compose exec uwsgi python manage.py spectacular --fail-on-warn
   ```
   (The first fails if you changed a model without a migration; the second fails if an API
   change broke the OpenAPI schema.)

7. **Reviewer mode (secondary).** When the input is someone else's PR rather than your own
   change:
   - `gh pr view <n> --json title,body,headRefName,files` and `gh pr diff <n>` to understand
     the change and its blast radius; check the target branch matches the release-line policy.
   - `gh pr checkout <n>`, bring the stack up, and apply **step 2** (reproduce the bug the PR
     claims to fix on the base branch, confirm it's gone on the PR branch) and **step 5** (run
     the concern lenses over the diff). Confirm the PR includes a behavioral test per step 4;
     if it doesn't, that's a finding.
   - **Read CI correctly.** The authoritative signals are the green GitHub Actions checks
     (`gh pr checks <n>`) and the real `gh pr diff <n>` (base...head). Third-party bot comments
     (e.g. DryRun "sensitive codepath modified by non-allowed author") are advisory and are
     often dismissed by maintainers as false positives — a huge "40+ sensitive files" wall is
     usually a **rewritten/recreated branch-history artifact**, not a real change. Verify against
     the actual diff; if it's 3 files, review 3 files. Also check that the **heavy suites
     actually ran** — if only lightweight jobs (autolabeler, analyzers) executed and Unit Tests
     / test-rest-framework never imported the code, a green board doesn't mean the code even
     imports (a missing import is invisible until the real suite runs).
   - **Report a severity-ranked findings summary to the user first.** Do not post to the PR
     automatically. Once the user approves, posting inline PR comments (e.g. via
     `/code-review --comment` or `gh`) is an explicit opt-in follow-up.

## Reviewing infra / Helm / deployment PRs

A recurring PR category touches the Helm chart (`helm/defectdojo/`), nginx config
(`nginx/`), or Docker entrypoints (`docker/`) rather than Django code. The concern lenses
still apply (security defaults, backward compatibility), but the checks are different:

- **The branch/release-line policy applies to chart and docker PRs too** — they are not
  exempt. A fix still targets `bugfix`, a feature `dev`, never `master`. Defer to `AGENTS.md`.
- **Know the three Helm CI jobs** (`.github/workflows/test-helm-chart.yml`) — each is an
  automatic blocker when it fails:
  - **`Lint chart (version)`** includes an **`artifacthub.io/changes` annotation check**: it
    fails on *any* chart change whose `helm/defectdojo/Chart.yaml` annotation wasn't updated
    versus the target branch. A chart PR with no new changelog annotation entry is red until
    fixed (this is the single most common chart-PR CI failure).
  - **`Update schema`** regenerates `values.schema.json` and fails on diff — the schema must be
    **generator-produced, not hand-edited**. A hand-edited schema is an automatic request-change.
  - **`Update documentation`** runs `helm-docs` — `README.md` must be regenerated from
    `values.yaml`, not written by hand.
- **New features must be opt-in and default-off.** Gate every new resource behind
  `{{- if .Values.X.enabled }}` with `enabled: false` by default, so `helm template` on defaults
  renders nothing new and existing installs are untouched. A new env/config default that applies
  to *all* installs (e.g. forcing `LC_ALL`) is a behavior change — flag it and make it overridable.
- **Template-correctness spot checks:** confirm `backendRefs`/service references point at real
  service names and ports; watch list-vs-map YAML rendering from a conditional `-` in the wrong
  place; guard `required` secret fields so an enabled-but-unconfigured block fails with a clear
  message instead of rendering empty strings.
- **Validate locally without the Django stack:** `helm lint helm/defectdojo`, then
  `helm template helm/defectdojo` with and without `--set X.enabled=true` to diff what the new
  block renders; run the schema/docs generators before pushing.

## Notes

- **Creds caveat:** `admin`/`admin` is a **dev-mode** convenience only. A production-style
  `docker compose up` generates a random admin password (see step 1).
- **Playwright expectations:** server-rendered Django, so drive full-page loads and real form
  submits; the CSRF token is a hidden input on each form and auth is a session cookie.
- **Never publish without approval:** posting review comments, opening/editing PRs, or any
  outward action waits for an explicit yes from the user (see the global action policy).
- **Branch & milestones:** `AGENTS.md` is the source of truth for which release line a change
  belongs on and the milestone rules for new PRs — defer to it.
- **Test runner:** always go through `./run-unittest.sh` / `run-tests.sh`; raw `pytest` and
  `manage.py test` are not the supported invocation here.
