Implement "Phase 10: Peripheral Model Modules — 10-PR Stack Continuation" from AGENTS.md.
Read that section first — it is the complete source of truth (bundles, line ranges,
stack/cascade mechanics, gotchas). Also read the Phase 0–9 playbook above it and follow
CLAUDE.local.md (run-unittest.sh + tee, PR body rules, never commit CLAUDE.md/.claude/).

## Goal
Finish the reorg by moving the ~45 peripheral model classes still in dojo/models.py into
their domain modules, as a full vertical slice (Phases 1–9) per module. Continue the existing
stack on top of reorg/finding-models (#14974).

## Order (bottom-up, do not parallelize across branches — they all touch the same monoliths)
1. FIRST: fold CWE + BurpRawRequestResponse into dojo/finding/ on the EXISTING branch
   reorg/finding-models (#14974). No new PR. Commit, force-push --force-with-lease to upstream.
2. Then PRs 6–10, each branched from its predecessor's tip:
   - reorg/peripheral-user            (Bundle A) ← reorg/finding-models
   - reorg/peripheral-tools-endpoint  (Bundle B) ← peripheral-user
   - reorg/peripheral-survey-benchmark(Bundle C) ← peripheral-tools-endpoint
   - reorg/peripheral-notes-files     (Bundle D) ← peripheral-survey-benchmark
   - reorg/peripheral-misc            (Bundle E) ← peripheral-notes-files
   Each: push to UPSTREAM, open as a DRAFT PR (gh pr create --draft --repo
   DefectDojo/django-DefectDojo --base <prev-branch> --head <this-branch>).

## Subagent strategy (cost + context, NOT parallelism)
All modules edit the same monolith files (dojo/models.py, forms.py, filters.py,
api_v2/serializers.py, api_v2/views.py, urls.py, apps.py). NEVER run two module subagents
concurrently — they would clobber each other's edits to those shared files. Process modules
ONE AT A TIME, bottom-up.

Use Sonnet subagents to offload mechanical bulk work and preserve your (Opus) context:
- You run Phase 0 pre-flight per module (grep consumers — don't trust memorized lists).
- Spawn ONE Sonnet subagent (model: sonnet) per module, sequentially. It does: move models+admin,
  add re-export stubs, string-ref cross-bundle FKs, move forms→ui/forms.py, filters→ui/filters.py,
  views/urls→ui/, and the API layer if one exists. Give it exact line ranges from AGENTS.md + the
  matching template (dojo/finding/, dojo/product/, dojo/test/, dojo/engagement/, or dojo/url//
  dojo/location/ for models-only).
- YOU handle the judgment parts: circular-import resolution, serializer get_fields() lazy
  cycle-breaks + extend_schema_field set_override, prefetcher full-reexport, shared-base
  decisions (FindingTagStringFilter trap).
- After each module: YOU run verify gates (docker manage.py check, makemigrations --check,
  ruff check, ./run-unittest.sh --test-case unittests.<module> 2>&1 | tee /tmp/test_<module>.log,
  grep the log). A Sonnet agent does not get to declare success — you confirm via gates before
  moving on.

## Per-bundle gotchas (also in AGENTS.md)
- survey & benchmark: NO api_v2 serializers/viewsets → skip Phases 6–9 for them (confirm w/ Phase 0).
- Question/Answer base classes live inside a `with warnings.catch_warnings():` block — preserve it.
- Benchmark_Requirement → M2M CWE: use string ref "dojo.CWE" (CWE moves to finding lower in stack).
- tool_config: move ToolConfigForm_Admin (ModelForm) + Tool_Configuration_Admin (ModelAdmin)
  from models.py into dojo/tool_config/admin.py.
- user (Bundle A): Dojo_User is an FK target everywhere — land it first; string-ref consumers.

## Commit/PR conventions
- One commit per phase group, same style as existing stack (e.g.
  "refactor(<module>): extract API layer into dojo/<module>/api/ [<module> Phase 6,7,8,9]").
- Every PR body (all 10) must carry the 10-item stack map already on #14970–#14974; copy that
  block, set the "◀ this PR" marker. Summary section only — NO test-plan section. Read existing
  body first (gh pr view <N> --json body -q '.body'); edit via --body-file or
  gh api -X PATCH /repos/DefectDojo/django-DefectDojo/pulls/<N> --input payload.json; verify after.
- After the 5 new draft PRs exist, BACKFILL their real PR numbers into all 10 PR bodies
  (replace the "_draft, to be opened_" placeholders for items 6–10).

## Stack hygiene
- If you edit a lower branch after upper ones exist, cascade:
  git rebase --onto <new-parent> <old-parent-sha> <branch> up the chain, then force-push all
  with --force-with-lease to upstream.
- Use --no-track when creating branches.

Work bottom-up, ONE module at a time. Stop and report if any verify gate fails and the fix
isn't mechanical. Narrate each module's pass/fail per CLAUDE.local.md.
