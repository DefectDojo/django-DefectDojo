#!/usr/bin/env bash
# Branch guard — makes the target release line explicit before any code lands.
#
# DefectDojo ships from three long-lived branches (see the "Branch Check" section
# of AGENTS.md):
#   bugfix  -> next PATCH release (fastest timeline)  <- bug fixes, regressions
#   dev     -> next MINOR release                     <- features, refactors
#   master  -> already released                       <- release / backport only
#
# A fix based on `dev` cannot ship until the next minor release, which is the most
# common way an urgent fix quietly misses the patch line. This hook reports the
# branch before work starts, and hard-blocks edits while on `master`.
#
# Three modes, all wired in .claude/settings.json:
#   session   SessionStart: report the branch and its release line into context.
#   edit      PreToolUse/Write|Edit: block edits while on `master`.
#   commit    PreToolUse/Bash(git commit*): same block for hand-staged changes.
#
# The `master` block clears only once an ack file exists for this session. An agent
# cannot create that file silently: `touch` is not allowlisted, so the ack command
# surfaces as a permission prompt a human has to approve. Do NOT add `touch` to
# permissions.allow — that would defeat the gate.
#
# Depends only on git and python3 (both already required to work on this repo).
set -uo pipefail

MODE="${1:-edit}"
INPUT="$(cat 2>/dev/null || true)"
PY="$(command -v python3 || command -v python || true)"

# Read a top-level or nested string field out of the hook's stdin JSON.
field() {
    [ -z "$PY" ] && return 0
    printf '%s' "$INPUT" | "$PY" -c '
import json, sys
try:
    cur = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for key in sys.argv[1].split("."):
    if not isinstance(cur, dict) or key not in cur:
        sys.exit(0)
    cur = cur[key]
print(cur if isinstance(cur, str) else "")
' "$1" 2>/dev/null
}

SESSION_ID="$(field 'session_id')"
[ -z "$SESSION_ID" ] && SESSION_ID="nosession"

REPO="${CLAUDE_PROJECT_DIR:-$PWD}"
g() { git -C "$REPO" "$@" 2>/dev/null; }
g rev-parse --git-dir >/dev/null || exit 0   # not a checkout, nothing to guard

BRANCH="$(g symbolic-ref --quiet --short HEAD)"

# Release line: patch | minor | released | detached | unknown. Topic branches are
# classified by what they contain, not by their name — dev is checked first,
# because dev contains bugfix once bugfix has been merged forward.
line_of() {
    case "$BRANCH" in
        bugfix) echo patch;    return ;;
        dev)    echo minor;    return ;;
        master) echo released; return ;;
    esac
    if [ -z "$BRANCH" ]; then
        local head master
        head="$(g rev-parse HEAD)"
        master="$(g rev-parse origin/master)"
        if [ -n "$head" ] && [ "$head" = "$master" ]; then echo released; else echo detached; fi
        return
    fi
    if g merge-base --is-ancestor origin/dev HEAD; then
        echo minor
    elif g merge-base --is-ancestor origin/bugfix HEAD; then
        echo patch
    else
        echo unknown
    fi
}
LINE="$(line_of)"

# ---------------------------------------------------------------- session mode
if [ "$MODE" = "session" ]; then
    [ -z "$PY" ] && exit 0   # informational only; nothing to report without python3
    case "$LINE" in
        patch)    DESC="ships in the next PATCH release (the fast line): bug fixes and regressions belong here, features do not" ;;
        minor)    DESC="ships in the next MINOR release: features and refactors belong here, and a BUG FIX based here will NOT ship until that minor release" ;;
        released) DESC="is already-released code: nothing belongs here except a release or backport task, and edits are BLOCKED until a human confirms" ;;
        detached) DESC="is a detached HEAD, so the release line is unclear" ;;
        *)        DESC="contains neither origin/bugfix nor origin/dev, so its base is stale or unmerged: run 'git fetch' and check the base before editing" ;;
    esac
    "$PY" -c '
import json, sys
branch, desc = sys.argv[1], sys.argv[2]
print(json.dumps({"hookSpecificOutput": {
    "hookEventName": "SessionStart",
    "additionalContext": (
        "Branch check: this checkout is on `" + branch + "`, which " + desc + ". "
        "State the branch and its release line back to the user before editing files. "
        "If the task is a bug fix sitting on the minor line, say so and offer to move it onto bugfix first."
    ),
}}))
' "${BRANCH:-detached HEAD}" "$DESC"
    exit 0
fi

# ------------------------------------------------------- edit / commit gating
if [ "$BRANCH" = "master" ]; then
    WHERE="the master branch"
elif [ -z "$BRANCH" ] && [ "$LINE" = "released" ]; then
    WHERE="a detached HEAD at origin/master"
else
    exit 0
fi

ACK_DIR="$(g rev-parse --absolute-git-dir)"
ACK_FILE="${ACK_DIR:-/nonexistent}/claude-branch-ack-${SESSION_ID}"
[ -f "$ACK_FILE" ] && exit 0

if [ "$MODE" = "commit" ]; then ACTION="Committing"; else ACTION="Editing files"; fi

REASON="BLOCKED: ${ACTION} is not allowed right now, because this checkout is on ${WHERE}, which holds already-released code. Bug fixes belong on \`bugfix\` (next patch release) and features on \`dev\` (next minor).

Do NOT retry, and do NOT work around this. Instead:
  1. Tell the user the checkout is on master and the change is blocked.
  2. Ask them to confirm this work is genuinely intended for master (a release or a backport), and WAIT for their reply.
  3. If they confirm, record it with:  touch '${ACK_FILE}'
     (that command prompts them for approval, which IS the confirmation) then continue.
  4. If they do not confirm, move the work first:  git switch -c <branch-name> origin/bugfix

The ack lasts for this session only."

if [ -n "$PY" ]; then
    "$PY" -c '
import json, sys
reason, where = sys.argv[1], sys.argv[2]
print(json.dumps({
    "systemMessage": "Branch guard: blocked — this checkout is on " + where + ". Confirm before any change lands here.",
    "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    },
}))
' "$REASON" "$WHERE" && exit 0
fi

# No python3: exit 2 also blocks the tool and feeds stderr back to the agent.
printf '%s\n' "$REASON" >&2
exit 2
