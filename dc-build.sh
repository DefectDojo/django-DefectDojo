#!/bin/bash

# for debugging
# set -o xtrace

bash ./docker/docker-compose-check.sh
if [[ $? -eq 1 ]]; then exit 1; fi

if [ $# -eq 0 ]; then
    echo "Building docker-compose"
else
    echo "Building docker-compose with additional parameters \"$@\" ..."
fi

if [ -z "$DD_ARCH" ]; then
    arch="$(uname -m)"
else
    arch="$DD_ARCH"
fi

# Building images for all configurations
# The docker build doesn't supply any environment variables to the Dockerfile, so we can use any profile.
case $arch in
    arm64)
        echo "Targeting arm64..."
        docker-compose --profile mysql-rabbitmq --profile postgres-redis --env-file ./docker/environments/postgres-rabbitmq.env -f docker-compose.yml -f docker-compose.override.arm64.yml build $@
        ;;
    *)
        docker-compose --profile mysql-rabbitmq --profile postgres-redis --env-file ./docker/environments/postgres-rabbitmq.env build $@
        ;;
esac
