#!/usr/bin/env bash
# Thin wrapper around the repo's sanctioned ./run-unittest.sh test runner.
#
# Runs a fully-qualified Django test target inside the uwsgi container
# (python manage.py test <target> --keepdb -v2) and tees the output to a log
# so failures are easy to re-read. The dev stack must already be up
# (./docker/setEnv.sh dev && docker compose up).
#
# Usage:
#   ./run-tests.sh <fully.qualified.TestTarget> [extra run-unittest.sh args]
#
# Examples:
#   ./run-tests.sh unittests.tools.test_acunetix_parser.TestAcunetixParser
#   ./run-tests.sh unittests.tools.test_acunetix_parser.TestAcunetixParser -f
#
# Do NOT invoke pytest or manage.py test directly — this path (via
# run-unittest.sh) is the supported one and matches how CI runs the suite.

set -euo pipefail

if [[ $# -lt 1 || "$1" == "-h" || "$1" == "--help" ]]; then
  echo "Usage: ./run-tests.sh <fully.qualified.TestTarget> [extra args]" >&2
  echo "Example: ./run-tests.sh unittests.tools.test_acunetix_parser.TestAcunetixParser" >&2
  exit 1
fi

TEST_TARGET="$1"
shift

# Locate the repo root (this script lives at .claude/skills/defectdojo-dev/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

if [[ ! -x "$REPO_ROOT/run-unittest.sh" ]]; then
  echo "ERROR: $REPO_ROOT/run-unittest.sh not found or not executable." >&2
  echo "Run this from a checkout of django-DefectDojo with the dev stack up." >&2
  exit 1
fi

LOG_DIR="${DD_TEST_LOG_DIR:-/tmp}"
LOG_FILE="${LOG_DIR%/}/dd-test-$(printf '%s' "$TEST_TARGET" | tr './:' '___').log"

echo "Running ${TEST_TARGET} (log: ${LOG_FILE})"
cd "$REPO_ROOT"
./run-unittest.sh --test-case "$TEST_TARGET" "$@" 2>&1 | tee "$LOG_FILE"
