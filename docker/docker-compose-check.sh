#!/bin/bash

main=$(docker compose  version  --short | cut -d '.' -f 1)
minor=$(docker compose  version  --short | cut -d '.' -f 2)
current=$(docker compose  version  --short)

echo 'Checking docker compose version'
if [[ $main -lt 2 ]]; then
  echo "$current is not a supported 'docker compose' version, please upgrade to the minimum supported version: 2.0"
  exit 1
elif [[ $main -eq 1 ]]; then
  if [[ $minor -lt 28 ]]; then
    echo "$current is not supported 'docker compose' version, please upgrade to minimal supported version:1.28"
    exit 1
  fi
fi

echo 'Supported docker compose version'