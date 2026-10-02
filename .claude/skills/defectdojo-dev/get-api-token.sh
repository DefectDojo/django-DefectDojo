#!/usr/bin/env bash
# Fetch a DefectDojo REST API token so you can test API endpoints.
#
# POSTs to /api/v2/api-token-auth/ and prints the raw token to stdout.
# Use it as an auth header:  Authorization: Token <printed-value>
#
# Env overrides (defaults suit local dev mode):
#   DD_BASE_URL  base URL of the app        (default http://localhost:8080)
#   DD_USER      username                   (default admin)
#   DD_PASSWORD  password                   (default admin)
#
# Examples:
#   ./get-api-token.sh
#   DD_USER=admin DD_PASSWORD='s3cr3t' DD_BASE_URL=http://localhost:8080 ./get-api-token.sh
#   TOKEN=$(./get-api-token.sh) && curl -s -H "Authorization: Token $TOKEN" \
#       "$DD_BASE_URL/api/v2/findings/?limit=1"
#
# If token auth is disabled server-side, the endpoint returns 4xx — get a token
# from the UI instead at:  $DD_BASE_URL/api/key-v2

set -euo pipefail

BASE_URL="${DD_BASE_URL:-http://localhost:8080}"
USER="${DD_USER:-admin}"
PASSWORD="${DD_PASSWORD:-admin}"
ENDPOINT="${BASE_URL%/}/api/v2/api-token-auth/"

# Capture body + HTTP status separately so we can give a useful error.
response="$(curl -sS -w $'\n%{http_code}' \
  -X POST "$ENDPOINT" \
  -H 'Content-Type: application/json' \
  -d "{\"username\": \"${USER}\", \"password\": \"${PASSWORD}\"}")"

http_code="$(printf '%s' "$response" | tail -n1)"
body="$(printf '%s' "$response" | sed '$d')"

if [[ "$http_code" != "200" ]]; then
  echo "ERROR: token request to ${ENDPOINT} returned HTTP ${http_code}" >&2
  echo "Response: ${body}" >&2
  echo "Hint: is the stack up (docker compose up) and are creds correct?" >&2
  echo "      If token auth is disabled, use the UI page ${BASE_URL%/}/api/key-v2" >&2
  exit 1
fi

# Prefer jq; fall back to a portable grep/sed extraction of the "token" field.
if command -v jq >/dev/null 2>&1; then
  printf '%s\n' "$(printf '%s' "$body" | jq -r '.token')"
else
  printf '%s\n' "$(printf '%s' "$body" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
fi
