#!/bin/bash

bash ./docker/docker-compose-check.sh
if [[ $? -eq 1 ]]; then exit 1; fi

if [ $# -eq 0 ]
then
    echo "Stopping docker compose"
else
    echo "Stopping docker compose with additional parameter $1 ..."
fi

# Stopping containers for all configurations
# The environment must be provided but it doesn't make a difference which one

# Compose V2 integrates compose functions into the Docker platform, continuing to support most of the previous docker-compose features and flags. You can run Compose V2 by replacing the hyphen (-) with a space, using docker compose, instead of docker-compose.
docker compose --profile mysql-rabbitmq --profile postgres-redis --env-file ./docker/environments/postgres-redis.env stop $1
