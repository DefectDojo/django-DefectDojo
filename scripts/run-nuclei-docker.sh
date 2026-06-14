#!/usr/bin/env bash
# Run ProjectDiscovery Nuclei in Docker with a persistent templates volume and rate limiting.
# Usage: ./scripts/run-nuclei-docker.sh <target-url> [nuclei-extra-args...]
# Env:   RATE_LIMIT, TEMPLATES_DIR, NUCLEI_IMAGE, UPDATE_TEMPLATES

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <target-url> [nuclei-extra-args...]" >&2
  exit 1
fi

TARGET="$1"
shift

RATE_LIMIT="${RATE_LIMIT:-150}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATES_DIR="${TEMPLATES_DIR:-${SCRIPT_DIR}/.nuclei-templates}"
IMAGE="${NUCLEI_IMAGE:-projectdiscovery/nuclei:latest}"
# Set to "true" to refresh templates before the scan (slower; use periodically).
UPDATE_TEMPLATES="${UPDATE_TEMPLATES:-false}"

mkdir -p "${TEMPLATES_DIR}"

DOCKER_RUN=(
  docker run --rm
  --pull always
  -v "${TEMPLATES_DIR}:/root/nuclei-templates"
  "${IMAGE}"
  -ud /root/nuclei-templates
)

if [[ "${UPDATE_TEMPLATES}" == "true" ]]; then
  echo "Updating Nuclei templates in ${TEMPLATES_DIR} ..."
  "${DOCKER_RUN[@]}" -update-templates
  echo ""
fi

echo "Scanning ${TARGET} (rate limit: ${RATE_LIMIT} req/s) ..."
"${DOCKER_RUN[@]}" -u "${TARGET}" -rate-limit "${RATE_LIMIT}" "$@"
