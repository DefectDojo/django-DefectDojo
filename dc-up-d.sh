#!/bin/bash

unset PROFILE

bash ./docker/docker-compose-check.sh
if [[ $? -eq 1 ]]; then exit 1; fi

if [ $# -eq 0 ]
then
    if [ -z $DD_PROFILE ]
    then
        echo "No profile supplied, running default: postgres-redis"
        PROFILE="postgres-redis"
        echo "Other supported profiles:
          postgres-redis*
          postgres-rabbitmq
          mysql-redis
          mysql-rabbitmq

        Usage example: ./dc-up-d.sh mysql-rabbitmq
        "
    else
        PROFILE=$DD_PROFILE
    fi
else
    PROFILE=$1
fi

echo "Starting docker compose with profile $PROFILE in the background ..."

# For Docker Compose V1 [From July 2023 Compose V1 stopped receiving updates. Reference: https://docs.docker.com/compose/reference/]
# docker-compose --profile $PROFILE --env-file ./docker/environments/$PROFILE.env up --no-deps -d

# Compose V2 integrates compose functions into the Docker platform, continuing to support most of the previous docker-compose features and flags. You can run Compose V2 by replacing the hyphen (-) with a space, using docker compose, instead of docker-compose.
docker compose --profile $PROFILE --env-file ./docker/environments/$PROFILE.env up --no-deps -d
