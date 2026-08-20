#!/usr/bin/env bash
# Local mirror of the CI meta-test (unittests/test_parsers.py) for a single parser.
# Checks that a parser directory has all the required sibling files and that its
# docs page carries the required front-matter, plus a couple of common code smells.
#
# This is a fast pre-flight only. The authoritative check is:
#   ./run-unittest.sh --test-case unittests.test_parsers
#
# Usage:
#   ./new-parser-checklist.sh <parser_dir>
# Examples:
#   ./new-parser-checklist.sh acunetix
#   ./new-parser-checklist.sh api_bugcrowd

set -uo pipefail

if [[ $# -ne 1 || "$1" == "-h" || "$1" == "--help" ]]; then
  echo "Usage: ./new-parser-checklist.sh <parser_dir>   (e.g. acunetix)" >&2
  exit 2
fi

DIR="$1"

# Repo root: this script lives at .claude/skills/defectdojo-parser/.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$REPO_ROOT"

# Docs category + name mirror test_parsers.py: an "api_" prefix maps to the api/
# docs folder with the prefix stripped; everything else is a file parser.
if [[ "$DIR" == api_* ]]; then
  CATEGORY="api"
  DOC_NAME="${DIR#api_}"
else
  CATEGORY="file"
  DOC_NAME="$DIR"
fi

PARSER_PY="dojo/tools/${DIR}/parser.py"
INIT_PY="dojo/tools/${DIR}/__init__.py"
TEST_PY="unittests/tools/test_${DIR}_parser.py"
SCANS_DIR="unittests/scans/${DIR}"
DOC_MD="docs/content/supported_tools/parsers/${CATEGORY}/${DOC_NAME}.md"

fail=0
pass()  { printf '  \033[32mOK\033[0m   %s\n' "$1"; }
bad()   { printf '  \033[31mMISS\033[0m %s\n' "$1"; fail=1; }
warn()  { printf '  \033[33mWARN\033[0m %s\n' "$1"; }

echo "Checking parser '${DIR}' (docs category: ${CATEGORY}) in ${REPO_ROOT}"
echo
echo "Required files:"
[[ -f "$INIT_PY"   ]] && pass "$INIT_PY"   || bad "$INIT_PY"
[[ -f "$PARSER_PY" ]] && pass "$PARSER_PY" || bad "$PARSER_PY"
[[ -f "$TEST_PY"   ]] && pass "$TEST_PY"   || bad "$TEST_PY"
[[ -d "$SCANS_DIR" ]] && pass "$SCANS_DIR/" || bad "$SCANS_DIR/ (sample scans directory)"
[[ -f "$DOC_MD"    ]] && pass "$DOC_MD"    || bad "$DOC_MD"

echo
echo "Sample scan files (recommended: no_vuln / one_vuln / many_vulns):"
if [[ -d "$SCANS_DIR" ]]; then
  count=$(find "$SCANS_DIR" -type f | wc -l | tr -d ' ')
  if [[ "$count" -eq 0 ]]; then
    warn "scans dir is empty — add at least no_vuln / one_vuln / many_vulns samples"
  else
    echo "  found ${count} sample file(s):"
    find "$SCANS_DIR" -type f -exec basename {} \; | sed 's/^/    - /'
    # Accept either common naming family: no_vuln/one_vuln/many_vulns or
    # no_finding(s)/one_finding/many_findings. Only warn if neither is present.
    have_scenario() { # $1 = grep -E pattern of acceptable name stems (optional tool-variant prefix allowed)
      find "$SCANS_DIR" -type f | grep -Eiq "/([^/]*_)?($1)\.[^/]+$"
    }
    have_scenario 'no_vuln|no_finding|no_findings|zero_finding|zero_findings|empty' \
      || warn "no empty-report sample (e.g. no_vuln / zero_finding) for the 0-findings test"
    have_scenario 'one_vuln|one_finding' \
      || warn "no single-finding sample (e.g. one_vuln / one_finding)"
    have_scenario 'many_vulns|many_findings' \
      || warn "no multi-finding sample (e.g. many_vulns / many_findings)"
  fi
fi

echo
echo "Docs front-matter:"
if [[ -f "$DOC_MD" ]]; then
  grep -q "title:" "$DOC_MD"        && pass "contains 'title:'"        || bad "docs missing 'title:'"
  grep -q "toc_hide: true" "$DOC_MD" && pass "contains 'toc_hide: true'" || bad "docs missing 'toc_hide: true'"
  if [[ "$CATEGORY" == "file" ]]; then
    grep -q "### Sample Scan Data" "$DOC_MD" \
      && pass "contains '### Sample Scan Data'" || bad "docs missing '### Sample Scan Data'"
    grep -q "https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans" "$DOC_MD" \
      && pass "contains scans-dir link" || bad "docs missing unittests/scans link"
  fi
fi

echo
echo "Code smells in ${PARSER_PY}:"
if [[ -f "$PARSER_PY" ]]; then
  if grep -Eq '(^|[^.])\blxml\b' "$PARSER_PY"; then
    warn "references 'lxml' — parsers must use defusedxml (XXE risk); rejected in review"
  else
    pass "no lxml reference"
  fi
  # .read() should have utf-8 nearby (mirrors the meta-test's ~4-line window).
  if grep -q '\.read()' "$PARSER_PY" && ! grep -A4 '\.read()' "$PARSER_PY" | grep -qi 'utf-8'; then
    warn ".read() without a nearby utf-8 encoding — meta-test requires utf-8 after .read()"
  else
    pass "no unencoded .read()"
  fi
  grep -q "class .*Parser" "$PARSER_PY" && pass "defines a *Parser class" \
    || warn "no '*Parser' class found — check the factory naming convention"
fi

echo
if [[ "$fail" -eq 0 ]]; then
  echo "All required files/docs present. Now run the real meta-test:"
else
  echo "Missing required items above. Fix them, then run the real meta-test:"
fi
echo "  ./run-unittest.sh --test-case unittests.test_parsers"
exit "$fail"
