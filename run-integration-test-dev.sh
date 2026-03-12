#!/bin/bash
# Run a single integration test against the running dev stack.
# Requires dev mode to be active (./docker/setEnv.sh dev && docker compose up).
#
# Usage:
#   ./run-integration-test-dev.sh tests/finding_test.py
#   ./run-integration-test-dev.sh tests/risk_acceptance_test.py

set -e

TEST_FILE="${1:?Usage: $0 <test-file>}"

docker compose --profile integration run --rm --no-deps \
  -e "DD_INTEGRATION_TEST_FILENAME=${TEST_FILE}" \
  -e "LOG_LEVEL=${LOG_LEVEL:-INFO}" \
  integration-tests
