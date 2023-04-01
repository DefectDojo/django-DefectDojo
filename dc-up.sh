#!/bin/bash

# for debugging
# set -o xtrace

unset PROFILE

bash ./docker/docker-compose-check.sh
if [[ $? -eq 1 ]]; then exit 1; fi

if [ $# -eq 0 ]; then
    PROFILE="${DD_PROFILE:-postgres-redis}"
else
    PROFILE="$1"
    shift 1
fi

# check whether this is a valid profile or not
if [ ! -f "./docker/environments/$PROFILE.env" ]; then
    echo "Invalid profile \"$PROFILE\". Valid profiles are:"
    ls -1 ./docker/environments | sed "s/\.env//g"
    exit 1
fi

if [ $# -eq 0 ]; then
    echo "Starting docker-compose with profile $PROFILE"
else
    echo "Starting docker-compose with profile $PROFILE and additional parameters \"$@\" ..."
fi

if [ -z "$DD_ARCH" ]; then
    arch="$(uname -m)"
else
    arch="$DD_ARCH"
fi

case $arch in
    arm64)
        echo "Targeting arm64..."
        docker-compose --profile "$PROFILE" --env-file ./docker/environments/$PROFILE.env -f docker-compose.yml -f docker-compose.override.arm64.yml up --no-deps $@
        ;;
    *)
        docker-compose --profile "$PROFILE" --env-file ./docker/environments/$PROFILE.env up --no-deps $@
        ;;
esac
