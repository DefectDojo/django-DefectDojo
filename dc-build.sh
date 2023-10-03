#!/bin/bash

bash ./docker/docker-compose-check.sh
if [[ $? -eq 1 ]]; then exit 1; fi

if [ $# -eq 0 ]
then
    echo "Building docker compose"
else
    echo "Building docker compose with additional parameter $1 ..."
fi

# Building images for all configurations
# The docker build doesn't supply any environment variables to the Dockerfile, so we can use any profile.

# For Docker Compose V1 [From July 2023 Compose V1 stopped receiving updates. Reference: https://docs.docker.com/compose/reference/]
# docker-compose --profile mysql-rabbitmq --profile postgres-redis --env-file ./docker/environments/postgres-redis.env build $1

# Compose V2 integrates compose functions into the Docker platform, continuing to support most of the previous docker-compose features and flags. You can run Compose V2 by replacing the hyphen (-) with a space, using docker compose, instead of docker-compose.
docker compose --profile mysql-rabbitmq --profile postgres-redis --env-file ./docker/environments/postgres-redis.env build $1
