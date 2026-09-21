---
name: defectdojo-parser
description: Author and review DefectDojo parsers (scan-report importers under dojo/tools/<name>/parser.py) to the project's real conventions — the factory contract, required Finding fields, deduplication registration in settings.dist.py, defusedxml/utf-8/Endpoint.from_uri rules, the 0/1/many unit-test set with attribute-level assertions, sample-file sanitization and size discipline, and the CI meta-test (unittests/test_parsers.py) that enforces the directory/docs layout. Use when writing a new parser, adding a scan type, reviewing a parser PR, or debugging a failing parser/test_parsers test.
---

# Write and review DefectDojo parsers

A parser ingests a security tool's scan report and returns unsaved `Finding` objects.
Parsers live at `dojo/tools/<parser_dir>/parser.py` and are **auto-discovered** by
`dojo/tools/factory.py` — there is no central list to edit. This skill is both an authoring
guide and a reviewer checklist; the two share the same rules, most of which are enforced by
the meta-test `unittests/test_parsers.py` (so violating them fails CI).

Canonical references in-repo:
- `docs/content/get_started/contributing/how-to-write-a-parser.md` — the authoritative guide.
- `docs/content/get_started/contributing/parser-documentation-template.md` — docs template.
- `unittests/test_parsers.py` — the meta-test that enforces layout/docs.
- `dojo/tools/factory.py` — discovery/registration.
- `dojo/tools/acunetix/parser.py` — a clean, well-documented reference parser.
- `dojo/tools/picus/parser.py`, `dojo/tools/alertlogic/parser.py` — clean CSV parsers with a
  `SEVERITY_MAPPING` that defaults unknown values to `Info`.

## Inputs

- **A new parser to write** (the scanner name and a sample report), **or**
- **A parser PR / directory to review** (parser dir name, e.g. `acunetix`).

## Helper script

`new-parser-checklist.sh <parser_dir>` (in this skill directory) mirrors the CI meta-test
locally: given a parser directory name it checks that the required files exist —
`dojo/tools/<dir>/parser.py`, `unittests/tools/test_<dir>_parser.py`,
`unittests/scans/<dir>/`, and the docs page (`docs/content/supported_tools/parsers/file/<dir>.md`,
or `.../api/<name>.md` for an `api_<name>` dir) — validates the docs front-matter
(`title:`, `toc_hide: true`, and for file parsers `### Sample Scan Data` + the scans link),
and flags common code smells (`lxml` import, `.read()` without utf-8). Run
`./run-unittest.sh --test-case unittests.test_parsers` for the real, authoritative check.

## Required layout (meta-test enforced)

| Artifact | Path |
|---|---|
| Package init (empty) | `dojo/tools/<dir>/__init__.py` |
| Parser code | `dojo/tools/<dir>/parser.py` |
| Sample scans dir | `unittests/scans/<dir>/` |
| Unit test (exact name) | `unittests/tools/test_<dir>_parser.py` |
| Docs (file parser) | `docs/content/supported_tools/parsers/file/<dir>.md` |
| Docs (API parser) | `docs/content/supported_tools/parsers/api/<name>.md` (dir is `api_<name>`) |
| Dedup/hashcode config | `dojo/settings/settings.dist.py` |

## Authoring rules

1. **Factory contract.** The class name is the directory name with underscores removed +
   `Parser` (module `dependency_check` → `DependencyCheckParser`). It must have an **empty
   constructor** and implement exactly:
   - `get_scan_types(self)` → list of scan-type strings
   - `get_label_for_scan_types(self, scan_type)` → short UI label
   - `get_description_for_scan_types(self, scan_type)` → long UI description
   - `get_findings(self, file, test)` → list of unsaved `Finding` objects

   Add `set_mode(self, mode)` only if the parser exposes more than one scan type (e.g. a
   `"... detailed"` variant). **Store no per-scan state on the instance** — the factory reuses
   one instance across all imports, so instance/class attributes leak between scans (this has
   caused real bugs; reset any state inside `get_findings`). The same leak happens **within a
   single call** when loop-local variables (`gem_name`, `severity`, a title, etc.) are only
   partially reset between records — a record missing an optional field then inherits the
   previous record's value. Reset every per-record variable to `None` at the top of each
   iteration, and build the finding only from fields actually present.

2. **Robust `get_findings`.** Guard every optional field: `data.get("k")`, `if "k" in data`,
   and `data.get("list") or []` (guards `null`). An unhandled `KeyError` becomes a 500 on
   import. Do **not** fill missing fields with placeholder junk like `"NA"` — leave the
   attribute unset. On a garbled or wrong-format file, **raise** `ValueError` with a hint
   rather than silently importing zero findings (a legitimately empty report is fine and
   should log an INFO line, not raise).

3. **Severity.** Valid severities are exactly `Info / Low / Medium / High / Critical`
   (`Finding.SEVERITIES`). Map vendor values through a dict with a default:
   `SEVERITY_MAPPING.get(raw, "Info")` (map synonyms like `Informational → Info`). Two distinct
   default cases — keep them straight:
   - **A value was present but unmapped** (a synonym you didn't handle fell through) → default
     to **`Info`**, and consider it a mapping gap to fix.
   - **The report carries no severity at all** for this tool → a documented non-`Info` default
     (e.g. `Medium`) can be reasonable, but it must be **called out in the parser's docs page**.
     An undocumented `Medium` default is a review finding.

   Do **not** hand-roll a CVSS-score→severity ladder — use `from dojo.utils import parse_cvss_data`
   (returns `severity`, `cvssv3`, `cvssv4`, `major_version`) or the `cvss` module.

4. **XML uses `defusedxml`, never `lxml` or stdlib ElementTree.** PRs with `lxml` are rejected
   outright (XXE risk).

5. **Endpoints / URLs.** Never hand-parse URLs. Use `Endpoint.from_uri(...)` (or the
   `hyperlink` module if unavoidable) and assign to `finding.unsaved_endpoints`.

6. **Encoding.** Any `.read()` in parser code must specify utf-8 within a few lines
   (`.read().decode("utf-8")` or `encoding="utf-8"`) — the meta-test fails otherwise.

## Deduplication (the single most common review miss)

Register the parser's dedup behavior in `dojo/settings/settings.dist.py`. Forgetting this is
the most frequent maintainer callout on parser PRs — without it the parser silently falls
back to the legacy algorithm. Two blocks must agree:
- **`DEDUPLICATION_ALGORITHM_PER_PARSER`** — map the scan type to one of `DEDUPE_ALGO_HASH_CODE`,
  `DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL`, or `DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE`.
- **`HASHCODE_FIELDS_PER_SCANNER`** — the list of `Finding` fields the hash is computed from
  (required whenever the algorithm uses `HASH_CODE`).

**Every scan type the parser returns from `get_scan_types()` needs its own dedup entries** —
the config is keyed by scan-type string, so a parser that emits two aliases (e.g. a friendly
name and a legacy one) must register both, or the unregistered alias silently falls back to
legacy dedup. Prefer emitting a single scan type unless there's a real reason for more.

Rules that recur in review:
- **`unique_id_from_tool` / `vuln_id_from_tool` must come verbatim from the report** — never a
  value the parser computes or derives. They must be unique per finding and stable across
  scans. If a stable id exists, prefer deduping on it directly rather than hashing it.
- **Keep `severity` out of the hash** unless it is provably stable across scans (it usually
  isn't — it drifts as occurrences change).

### Dedup changes to existing data (close the open loop)

**Any change that alters the dedup key for an existing scan type is a data-migration
concern, not just a code change — treat it as a release-gating review item.** The dedup key
changes when a PR touches `HASHCODE_FIELDS_PER_SCANNER`, `DEDUPLICATION_ALGORITHM_PER_PARSER`,
how `unique_id_from_tool`/`vuln_id_from_tool` is populated, or any parser field that feeds the
hash (title, component, file_path, line, etc.). Also flag parser output changes that shift
those fields even when the config is untouched.

Why it matters for customers with existing data: **`hash_code` is computed once at import and
stored on the `Finding` row — it is not recomputed retroactively.** So after the change, old
findings keep their old key and new imports compute a different one. Two concrete failures:
- **Duplicates instead of dedup** — the next scan's findings no longer match the stored ones,
  so they import as brand-new findings.
- **The close/reopen loop breaks** — reimport closes findings absent from the new report and
  reopens ones that return, by matching on the dedup key. When the key shifts, reimport can
  fail to mitigate findings that were actually fixed, or **reopen findings that were already
  closed** — noisy and alarming for users.

What the PR (and your review) must ensure:
- **Call it out explicitly** in the PR description and the release note — this is a behavior
  change for existing data, not a silent internal tweak.
- **Provide the recompute path.** Existing rows need `hash_code` recomputed and dedup re-run:
  `python manage.py dedupe --parser "<Scan Type>" --hash_code_only` (recompute only), then
  `--dedupe_only` (re-run dedup), or the full `manage.py dedupe`. Note this is heavy on large
  instances (mass update over all findings for the scan type, async by default) — it's ops
  guidance for the customer, not something the import path does automatically.
- **Validate the config** with `python manage.py validatededupeconfig`.
- **Prefer additive / opt-in.** Reopening a customer's closed findings on upgrade is a strong
  reason to reject or redesign; favor changes that don't retroactively alter the key, or that
  ship with a clear recompute runbook.

## Unit-test strategy

- **Minimum three sample files: `no_vuln`, `one_vuln`, `many_vulns`** (correct extension),
  with matching test methods. Assert the empty file yields `0` findings and the multi file the
  exact count.
- **Assert concrete attributes, not just counts** — for representative findings check `title`,
  `severity` (`assertIn(finding.severity, Finding.SEVERITIES)`), `active`/`verified`/
  `duplicate`, `unique_id_from_tool`/`vuln_id_from_tool`, `cwe`, CVSS fields,
  `vulnerability_ids`, dates, tags. Wrap per-finding checks in `with self.subTest(...)`.
- **Open sample files with the `with ... .open(encoding="utf-8")` pattern**, using
  `get_unit_tests_scans_path("<dir>") / "one_vuln.json"` from `unittests/dojo_test_case.py`.
  Subclass `DojoTestCase`.
- **Endpoint parsers:** call `endpoint.clean()` on every `finding.unsaved_endpoints` in a test
  to prove RFC-valid endpoints.
- **API parsers:** also add `unittests/tools/test_api_<name>_importer.py` and mock the API with
  `unittest.mock.patch`.
- **Regression fixtures:** when fixing a specific bug, add a small targeted sample named
  `issue_<number>.<ext>` (the repo-wide convention) rather than bloating an existing file.
- Run: `./run-unittest.sh --test-case unittests.tools.test_<dir>_parser.<TestClass>`.

## Sample-file rules (sanitization & size)

- **Sanitize sample scans.** Strip real IPs, hostnames, tokens/credentials, customer names,
  and other PII — use `example.com` / obviously fabricated data. (This is a strong convention
  the maintainers hold; it is not written as a numeric rule in the repo, so apply judgment and
  call it out explicitly in review.)
- **Keep the set minimal.** `no_vuln` / `one_vuln` / `many_vulns` is the baseline; add small,
  targeted cases for specific edge conditions instead of committing large real-world dumps.
  There is no hard committed-fixture size cap, but the runtime upload limit is
  `DD_SCAN_FILE_MAX_SIZE` (default 100 MB) — samples should be far smaller. Prefer the
  smallest report that still exercises the behavior.

## Documentation (meta-test enforced)

The docs page must exist at the path above and contain front-matter `title:` and
`toc_hide: true`. **File parsers** must also include a `### Sample Scan Data` heading and a
link to `https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans`. Follow
`parser-documentation-template.md` (file types + how to export, field mapping, dedup handling,
default severity, sample link). **Do not put source-code line numbers in the field-mapping
table** — they drift and get rejected in review.

## Reviewer checklist (highest-frequency issues)

1. **Dedup registered** in `settings.dist.py` — both the algorithm map and (for hashcode)
   `HASHCODE_FIELDS_PER_SCANNER`?
2. **`unique_id_from_tool` taken verbatim** from the report, not computed?
3. **`severity` excluded from the hash** unless provably stable?
4. **Dedup-key change on an existing scan type?** If the PR shifts `HASHCODE_FIELDS_PER_SCANNER`,
   the algorithm, `unique_id_from_tool`, or a hashed field, is there a recompute/reimport
   runbook (`manage.py dedupe`) and a release note? Existing findings won't recompute
   `hash_code` automatically, so imports can duplicate and the close/reopen loop can break.
5. **Unrecognized file raises**, doesn't silently import 0 findings?
6. **0 / 1 / many sample files + attribute-level assertions**, opened with `with`?
7. **Sample files sanitized and minimal** (no real IPs/hosts/tokens/customers; no giant dumps)?
8. **Docs page present** with `title:`, `toc_hide: true`, `### Sample Scan Data` + scans link,
   and **no source line numbers**?
9. **Ruff clean; utf-8 after `.read()`; `defusedxml` (no lxml); `Endpoint.from_uri()`**?
10. **No leaked state** — no per-instance attributes across imports, and per-record loop
    variables fully reset each iteration (a record missing an optional field must not inherit
    the previous record's value)?

## PR hygiene (parser PRs specifically)

- **Keep the diff to the parser's own files.** A parser PR should touch `dojo/tools/<dir>/`,
  its test + samples, its docs page, and (for dedup) `settings.dist.py` — nothing else. Flag
  unrelated edits riding along, especially `requirements.txt` / dependency bumps; ask for them
  to be split out.
- **Screen the PR description.** Community parser PRs sometimes carry vendor marketing or paid-
  service links in the body. Flag promotional content for a maintainer — it's not a code defect
  but the project cares about it.
- **Trust green Actions + the real diff, not bot noise.** The authoritative signals are the
  green GitHub Actions checks and the actual `gh pr diff` (base...head). Third-party bot walls
  (e.g. DryRun "sensitive codepath modified") are advisory and are routinely dismissed by
  maintainers as false positives — don't treat them as blockers; verify against the real diff.

## Notes

- **New parser = a feature → targets `dev`**; a parser bugfix targets `bugfix`. Label the PR
  `Import Scans`. Defer to `AGENTS.md` for the branch/milestone policy.
- **New API parsers from the community are currently not accepted** (supportability) — flag
  this in review of an inbound API parser.
- A scaffolding template exists: `https://github.com/DefectDojo/cookiecutter-scanner-parser`.
- Common meta-test exemptions (shared/common modules) are hard-coded in
  `unittests/test_parsers.py` (e.g. `wizcli_common_parsers`, `sysdig_common`,
  `checkmarx_osa`) — a genuinely new parser is not one of these.
