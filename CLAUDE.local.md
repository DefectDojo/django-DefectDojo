# Claude Code Instructions

Follow all guidelines in [AGENTS.md](AGENTS.md). Key points repeated here for emphasis:

## Pull Request Descriptions

- Include a **Summary** section only — bullet points describing what changed and why.
- **Do NOT add any of the following sections**: "Test plan", "Testing", "How to test", or any other testing-related section. DefectDojo's PR template does not use one.
- **NEVER overwrite an existing PR description** without first reading it with `gh pr view <PR_NUMBER> --json body -q '.body'`.
- **NEVER mention DefectDojo Pro** in PRs, issues, or comments targeting the open source repo.
- **Always edit PR bodies via a file**, never inline. `gh pr edit <N> --body "$(cat <<'EOF' ... EOF)"` silently exits 1 on this repo because the Projects (classic) GraphQL deprecation warning trips gh's error path. Use one of:
  - `gh pr edit <N> --body-file /tmp/pr_body.md`
  - `gh api -X PATCH /repos/<owner>/<repo>/pulls/<N> --input <payload.json>` (REST, fully bypasses the GraphQL warning)
  Always verify with `gh pr view <N> --json body -q '.body'` after — `gh pr edit` may print no error but still leave the body unchanged.

## PR URLs

- Always format PR URLs as markdown links: `[PR #123](https://github.com/owner/repo/pull/123)`

## Git Commits

- **NEVER commit `CLAUDE.md`** — it is a local instruction file, not part of the upstream codebase.
- **NEVER commit files from `.claude/`** — these are local session artifacts.

## Running Unit Tests

- **Always use `./run-unittest.sh`** to run unit tests — never `python -m pytest` or `python manage.py test` directly:
  ```bash
  ./run-unittest.sh --test-case unittests.test_module.TestClass 2>&1 | tee /tmp/test_output.log
  ```
- **ALWAYS pipe output through `tee` to capture it to a file.** This is mandatory — it lets you grep the results without re-running expensive tests.
- After running, analyze with `grep` on the captured file, not by re-running:
  ```bash
  grep -E "PASSED|FAILED|ERROR|error" /tmp/test_output.log
  ```
- **Narrate every test iteration**: report pass/fail immediately after each run, explain what failed and what you plan to fix before making changes, then explain what you changed before re-running.
